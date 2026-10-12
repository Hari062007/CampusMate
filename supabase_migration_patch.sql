-- ============================================================================
-- CAMPUSMATE SUPABASE MIGRATION PATCH
-- File: supabase_migration_patch.sql
-- ============================================================================
-- Purpose:
-- Safe, idempotent migration patch to be applied on top of supabase_schema.sql.
-- Addresses:
-- 1. Automated, secure profile & preference provisioning on auth.users signup
--    (with strict, case-insensitive anti-collision checks that protect identities)
-- 2. Hardened SECURITY DEFINER functions with search_path protection
-- 3. Targeted, explicit least-privilege RPC permissions without breaking
--    PostgreSQL and Supabase extension functions
-- 4. Automatic assignment task fan-out and notifications (duplicate-safe)
-- 5. Anti-tampering safeguards for faculty verification privileges on INSERT and UPDATE
--    (with documented administrative procedures)
-- 6. Missing RLS policies for assignment updates, deletes, and post moderation
--
-- Note: DO NOT run automatically. Apply in Supabase SQL Editor during migration.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- SECTION 1: PROFILES TABLE ENHANCEMENTS & FACULTY PRIVILEGE SAFEGUARDS
-- ----------------------------------------------------------------------------

-- Add is_faculty column if not already present
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'profiles'
          AND column_name = 'is_faculty'
    ) THEN
        ALTER TABLE public.profiles ADD COLUMN is_faculty BOOLEAN NOT NULL DEFAULT false;
    END IF;
END $$;

-- Anti-tampering trigger: Prevent ordinary students and classroom owners from
-- self-assigning faculty privileges on BOTH INSERT and UPDATE.
--
-- HOW TO ASSIGN FACULTY PRIVILEGES (ADMINISTRATIVE METHODS):
-- Method 1 (Supabase Dashboard): Navigate to Table Editor -> 'profiles', locate
--          the verified instructor/faculty member, and set 'is_faculty' to true.
-- Method 2 (SQL Editor): Run an administrative SQL update as database owner:
--          UPDATE public.profiles SET is_faculty = true WHERE lower(college_email) = 'faculty@college.edu';
-- Method 3 (Service Role Script): Execute an administrative update using a backend
--          script authenticated with the Supabase Service Role Key (SUPABASE_SERVICE_ROLE_KEY).
CREATE OR REPLACE FUNCTION public.protect_profile_faculty_status()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Case A: Direct client INSERT attempting to set is_faculty = true
    IF TG_OP = 'INSERT' THEN
        IF NEW.is_faculty THEN
            IF current_user IN ('authenticated', 'anon') OR (auth.uid() IS NOT NULL AND current_user NOT IN ('service_role', 'postgres', 'supabase_admin')) THEN
                RAISE EXCEPTION 'Access denied: Students and classroom owners cannot self-assign faculty status.';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    -- Case B: Client UPDATE attempting to modify is_faculty
    IF TG_OP = 'UPDATE' THEN
        IF NEW.is_faculty IS DISTINCT FROM OLD.is_faculty THEN
            -- Block ordinary PostgREST client roles
            IF current_user IN ('authenticated', 'anon') THEN
                RAISE EXCEPTION 'Access denied: Students and classroom owners cannot self-assign faculty status.';
            END IF;

            -- Defense-in-depth: If an authenticated session is active, verify caller is strictly an admin
            IF auth.uid() IS NOT NULL AND current_user NOT IN ('service_role', 'postgres', 'supabase_admin') THEN
                RAISE EXCEPTION 'Access denied: Faculty status can only be granted by an institution administrator.';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_profile_faculty ON public.profiles;
CREATE TRIGGER trg_protect_profile_faculty
    BEFORE INSERT OR UPDATE ON public.profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.protect_profile_faculty_status();

-- ----------------------------------------------------------------------------
-- SECTION 2: AUTOMATIC USER PROVISIONING TRIGGER (auth.users -> profiles)
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_full_name TEXT;
    v_roll_number TEXT;
    v_email TEXT;
BEGIN
    -- Extract and sanitize inputs
    v_email := trim(lower(coalesce(NEW.email, '')));
    v_full_name := trim(coalesce(NEW.raw_user_meta_data->>'full_name', ''));
    v_roll_number := trim(coalesce(NEW.raw_user_meta_data->>'roll_number', ''));

    -- 1. Strict validation of email format
    IF v_email = '' OR v_email !~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' THEN
        RAISE EXCEPTION 'Registration failed: A valid college email address is required.';
    END IF;

    -- 2. Anti-collision check (Case-Insensitive): Protect existing identities and foreign keys.
    -- If this college email is already bound to a different profile, DO NOT transfer
    -- or overwrite the existing profile ID. Abort the signup transaction immediately.
    IF EXISTS (
        SELECT 1 FROM public.profiles
        WHERE lower(college_email) = v_email AND id <> NEW.id
    ) THEN
        RAISE EXCEPTION 'Registration failed: An account with college email "%" already exists. Please sign in with your existing account.', v_email;
    END IF;

    -- 3. Fallback safety for full name
    IF v_full_name = '' THEN
        v_full_name := split_part(v_email, '@', 1);
        IF v_full_name = '' THEN
            v_full_name := 'Student';
        END IF;
    END IF;

    -- 4. Fallback safety for roll number
    IF v_roll_number = '' THEN
        v_roll_number := 'UNASSIGNED';
    END IF;

    -- 5. Insert profile record safely
    INSERT INTO public.profiles (
        id,
        full_name,
        college_email,
        roll_number,
        is_faculty,
        created_at,
        updated_at
    )
    VALUES (
        NEW.id,
        v_full_name,
        v_email,
        v_roll_number,
        false,
        now(),
        now()
    )
    ON CONFLICT (id) DO UPDATE SET
        full_name = EXCLUDED.full_name,
        roll_number = EXCLUDED.roll_number,
        college_email = EXCLUDED.college_email,
        updated_at = now();

    -- 6. Provision default notification preferences
    INSERT INTO public.notification_preferences (
        user_id,
        reminder_hours_before,
        email_notifications_enabled,
        updated_at
    )
    VALUES (
        NEW.id,
        24,
        true,
        now()
    )
    ON CONFLICT (user_id) DO NOTHING;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user();

-- ----------------------------------------------------------------------------
-- SECTION 3: AUTOMATIC ASSIGNMENT DISTRIBUTION TRIGGER (user_tasks sync)
-- ----------------------------------------------------------------------------

-- Fans out tasks and notifications to all approved members when an assignment is shared.
-- Operates as SECURITY DEFINER to bypass client RLS limitations across member rows.
CREATE OR REPLACE FUNCTION public.handle_new_assignment()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_member RECORD;
    v_cls_name TEXT;
BEGIN
    SELECT name INTO v_cls_name FROM public.classrooms WHERE id = NEW.classroom_id;

    -- Loop through all currently approved members of this classroom
    FOR v_member IN
        SELECT user_id FROM public.classroom_members
        WHERE classroom_id = NEW.classroom_id AND membership_status = 'approved'
    LOOP
        -- 1. Insert task into user_tasks (ON CONFLICT DO NOTHING guarantees no duplicates)
        INSERT INTO public.user_tasks (
            user_id,
            assignment_id,
            classroom_id,
            title,
            due_date,
            status,
            created_at
        )
        VALUES (
            v_member.user_id,
            NEW.id,
            NEW.classroom_id,
            NEW.title,
            NEW.due_date,
            'pending',
            now()
        )
        ON CONFLICT (user_id, assignment_id) DO NOTHING;

        -- 2. Send notification to member (skip the author who posted it)
        IF v_member.user_id <> NEW.created_by THEN
            INSERT INTO public.notifications (
                user_id,
                classroom_id,
                title,
                message,
                type,
                created_at
            )
            VALUES (
                v_member.user_id,
                NEW.classroom_id,
                'New Assignment: ' || NEW.title,
                'Subject: ' || NEW.subject || ' | Due: ' || to_char(NEW.due_date, 'Mon DD, YYYY HH24:MI') || ' in ' || coalesce(v_cls_name, 'your classroom'),
                'assignment_shared',
                now()
            );
        END IF;
    END LOOP;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_new_assignment_distribution ON public.assignments;
CREATE TRIGGER trg_new_assignment_distribution
    AFTER INSERT ON public.assignments
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_assignment();

-- Sync task title / due date if the assignment is edited later
CREATE OR REPLACE FUNCTION public.handle_update_assignment()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    UPDATE public.user_tasks
    SET title = NEW.title, due_date = NEW.due_date
    WHERE assignment_id = NEW.id;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_update_assignment_distribution ON public.assignments;
CREATE TRIGGER trg_update_assignment_distribution
    AFTER UPDATE OF title, due_date ON public.assignments
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_update_assignment();

-- ----------------------------------------------------------------------------
-- SECTION 4: FACULTY VERIFICATION SAFEGUARDS ON POSTS & RLS POLICY ENHANCEMENTS
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.verify_post_faculty_status()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_is_faculty BOOLEAN := false;
BEGIN
    IF NEW.is_faculty_verified THEN
        SELECT is_faculty INTO v_is_faculty
        FROM public.profiles
        WHERE id = NEW.author_id;

        IF NOT FOUND OR NOT coalesce(v_is_faculty, false) THEN
            RAISE EXCEPTION 'Access denied: Only authorized faculty members can publish verified announcements.';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_verify_post_faculty ON public.classroom_posts;
CREATE TRIGGER trg_verify_post_faculty
    BEFORE INSERT OR UPDATE ON public.classroom_posts
    FOR EACH ROW
    EXECUTE FUNCTION public.verify_post_faculty_status();

-- RLS Policy Enhancements: Enable assignment updates, deletes, and post deletion
DO $$
BEGIN
    -- Assignment UPDATE policy for creators or classroom owners
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'assignments'
          AND policyname = 'Creators or owners can update assignments'
    ) THEN
        CREATE POLICY "Creators or owners can update assignments"
            ON public.assignments FOR UPDATE
            TO authenticated
            USING (
                created_by = auth.uid() OR public.is_classroom_owner(classroom_id, auth.uid())
            )
            WITH CHECK (
                created_by = auth.uid() OR public.is_classroom_owner(classroom_id, auth.uid())
            );
    END IF;

    -- Assignment DELETE policy for creators or classroom owners
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'assignments'
          AND policyname = 'Creators or owners can delete assignments'
    ) THEN
        CREATE POLICY "Creators or owners can delete assignments"
            ON public.assignments FOR DELETE
            TO authenticated
            USING (
                created_by = auth.uid() OR public.is_classroom_owner(classroom_id, auth.uid())
            );
    END IF;

    -- Classroom Posts DELETE policy for authors or classroom owners
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'classroom_posts'
          AND policyname = 'Authors or owners can delete posts'
    ) THEN
        CREATE POLICY "Authors or owners can delete posts"
            ON public.classroom_posts FOR DELETE
            TO authenticated
            USING (
                author_id = auth.uid() OR public.is_classroom_owner(classroom_id, auth.uid())
            );
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- SECTION 5: SECURITY DEFINER HARDENING (search_path & Authorization)
-- ----------------------------------------------------------------------------

-- 1. is_approved_member
CREATE OR REPLACE FUNCTION public.is_approved_member(p_classroom_id UUID, p_user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.classroom_members
        WHERE classroom_id = p_classroom_id
          AND user_id = p_user_id
          AND membership_status = 'approved'
    );
$$;

-- 2. is_classroom_owner
CREATE OR REPLACE FUNCTION public.is_classroom_owner(p_classroom_id UUID, p_user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.classrooms
        WHERE id = p_classroom_id
          AND owner_id = p_user_id
    );
$$;

-- 3. create_classroom
CREATE OR REPLACE FUNCTION public.create_classroom(
    p_name TEXT,
    p_description TEXT DEFAULT ''
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id UUID;
    v_classroom_id UUID;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    IF trim(p_name) = '' THEN
        RAISE EXCEPTION 'Classroom name cannot be empty.';
    END IF;

    INSERT INTO public.classrooms (name, description, owner_id)
    VALUES (trim(p_name), trim(p_description), v_user_id)
    RETURNING id INTO v_classroom_id;

    INSERT INTO public.classroom_members (classroom_id, user_id, role, membership_status)
    VALUES (v_classroom_id, v_user_id, 'owner', 'approved');

    RETURN jsonb_build_object(
        'success', true,
        'classroom_id', v_classroom_id,
        'name', trim(p_name)
    );
END;
$$;

-- 4. create_invitation_link
CREATE OR REPLACE FUNCTION public.create_invitation_link(
    p_classroom_id UUID,
    p_token_hash TEXT,
    p_expires_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id UUID;
    v_invitation_id UUID;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    IF NOT public.is_classroom_owner(p_classroom_id, v_user_id) THEN
        RAISE EXCEPTION 'Access denied. Only the classroom owner can generate invitation links.';
    END IF;

    UPDATE public.classroom_invitations
    SET revoked_at = timezone('utc'::text, now())
    WHERE classroom_id = p_classroom_id AND revoked_at IS NULL;

    INSERT INTO public.classroom_invitations (classroom_id, token_hash, created_by, expires_at)
    VALUES (p_classroom_id, p_token_hash, v_user_id, p_expires_at)
    RETURNING id INTO v_invitation_id;

    RETURN jsonb_build_object(
        'success', true,
        'invitation_id', v_invitation_id,
        'classroom_id', p_classroom_id,
        'expires_at', p_expires_at
    );
END;
$$;

-- 5. revoke_invitation_link
CREATE OR REPLACE FUNCTION public.revoke_invitation_link(
    p_classroom_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id UUID;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    IF NOT public.is_classroom_owner(p_classroom_id, v_user_id) THEN
        RAISE EXCEPTION 'Access denied. Only the classroom owner can revoke invitation links.';
    END IF;

    UPDATE public.classroom_invitations
    SET revoked_at = timezone('utc'::text, now())
    WHERE classroom_id = p_classroom_id AND revoked_at IS NULL;

    RETURN jsonb_build_object('success', true, 'message', 'Invitation link revoked.');
END;
$$;

-- 6. get_invitation_preview
CREATE OR REPLACE FUNCTION public.get_invitation_preview(
    p_token_hash TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_record RECORD;
    v_user_id UUID;
    v_request_status TEXT := NULL;
    v_is_member BOOLEAN := false;
BEGIN
    v_user_id := auth.uid();

    SELECT ci.id, ci.classroom_id, ci.expires_at, ci.revoked_at,
           c.name AS classroom_name, c.description,
           p.full_name AS owner_name
    INTO v_record
    FROM public.classroom_invitations ci
    JOIN public.classrooms c ON c.id = ci.classroom_id
    JOIN public.profiles p ON p.id = c.owner_id
    WHERE ci.token_hash = p_token_hash;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('valid', false, 'error', 'Invalid invitation link.');
    END IF;

    IF v_record.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('valid', false, 'error', 'Invitation Revoked', 'status', 'revoked');
    END IF;

    IF v_record.expires_at IS NOT NULL AND v_record.expires_at < timezone('utc'::text, now()) THEN
        RETURN jsonb_build_object('valid', false, 'error', 'Invitation Expired', 'status', 'expired');
    END IF;

    IF v_user_id IS NOT NULL THEN
        SELECT status INTO v_request_status
        FROM public.classroom_join_requests
        WHERE classroom_id = v_record.classroom_id AND user_id = v_user_id;

        SELECT EXISTS (
            SELECT 1 FROM public.classroom_members
            WHERE classroom_id = v_record.classroom_id AND user_id = v_user_id AND membership_status = 'approved'
        ) INTO v_is_member;
    END IF;

    RETURN jsonb_build_object(
        'valid', true,
        'classroom_id', v_record.classroom_id,
        'classroom_name', v_record.classroom_name,
        'description', v_record.description,
        'owner_name', v_record.owner_name,
        'request_status', v_request_status,
        'is_member', v_is_member
    );
END;
$$;

-- 7. request_to_join
CREATE OR REPLACE FUNCTION public.request_to_join(
    p_token_hash TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id UUID;
    v_classroom_id UUID;
    v_owner_id UUID;
    v_applicant_name TEXT;
    v_inv_record RECORD;
    v_existing_req RECORD;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required to submit join request.';
    END IF;

    SELECT ci.classroom_id, ci.expires_at, ci.revoked_at, c.owner_id
    INTO v_inv_record
    FROM public.classroom_invitations ci
    JOIN public.classrooms c ON c.id = ci.classroom_id
    WHERE ci.token_hash = p_token_hash;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid invitation link.';
    END IF;

    IF v_inv_record.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'This invitation link has been revoked.';
    END IF;

    IF v_inv_record.expires_at IS NOT NULL AND v_inv_record.expires_at < timezone('utc'::text, now()) THEN
        RAISE EXCEPTION 'This invitation link has expired.';
    END IF;

    v_classroom_id := v_inv_record.classroom_id;
    v_owner_id := v_inv_record.owner_id;

    IF public.is_approved_member(v_classroom_id, v_user_id) THEN
        RETURN jsonb_build_object('success', false, 'message', 'You are already an approved member of this classroom.');
    END IF;

    SELECT * INTO v_existing_req
    FROM public.classroom_join_requests
    WHERE classroom_id = v_classroom_id AND user_id = v_user_id;

    IF FOUND THEN
        IF v_existing_req.status = 'pending' THEN
            RETURN jsonb_build_object('success', true, 'status', 'pending', 'message', 'Your request is already pending approval.');
        ELSIF v_existing_req.status = 'approved' THEN
            RETURN jsonb_build_object('success', true, 'status', 'approved', 'message', 'Your request has already been approved.');
        ELSIF v_existing_req.status IN ('rejected', 'cancelled') THEN
            UPDATE public.classroom_join_requests
            SET status = 'pending', requested_at = timezone('utc'::text, now()), reviewed_at = NULL, reviewed_by = NULL
            WHERE id = v_existing_req.id;
        END IF;
    ELSE
        INSERT INTO public.classroom_join_requests (classroom_id, user_id, status)
        VALUES (v_classroom_id, v_user_id, 'pending');
    END IF;

    SELECT full_name INTO v_applicant_name FROM public.profiles WHERE id = v_user_id;

    INSERT INTO public.notifications (user_id, classroom_id, title, message, type)
    VALUES (
        v_owner_id,
        v_classroom_id,
        'New Join Request',
        coalesce(v_applicant_name, 'A student') || ' has requested to join your classroom.',
        'join_request'
    );

    RETURN jsonb_build_object(
        'success', true,
        'status', 'pending',
        'message', 'Your request has been sent. You can access this classroom after the owner approves your request.'
    );
END;
$$;

-- 8. approve_join_request
CREATE OR REPLACE FUNCTION public.approve_join_request(
    p_request_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id UUID;
    v_req RECORD;
    v_classroom_name TEXT;
    v_assign RECORD;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    SELECT r.*, c.name AS classroom_name, c.owner_id
    INTO v_req
    FROM public.classroom_join_requests r
    JOIN public.classrooms c ON c.id = r.classroom_id
    WHERE r.id = p_request_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Join request not found.';
    END IF;

    IF v_req.owner_id != v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: Only the designated classroom owner can approve join requests.';
    END IF;

    UPDATE public.classroom_join_requests
    SET status = 'approved', reviewed_at = timezone('utc'::text, now()), reviewed_by = v_user_id
    WHERE id = p_request_id;

    INSERT INTO public.classroom_members (classroom_id, user_id, role, membership_status, joined_at)
    VALUES (v_req.classroom_id, v_req.user_id, 'member', 'approved', timezone('utc'::text, now()))
    ON CONFLICT (classroom_id, user_id)
    DO UPDATE SET membership_status = 'approved', joined_at = timezone('utc'::text, now());

    FOR v_assign IN
        SELECT id, title, due_date
        FROM public.assignments
        WHERE classroom_id = v_req.classroom_id
          AND due_date >= timezone('utc'::text, now())
    LOOP
        INSERT INTO public.user_tasks (user_id, assignment_id, classroom_id, title, due_date, status)
        VALUES (v_req.user_id, v_assign.id, v_req.classroom_id, v_assign.title, v_assign.due_date, 'pending')
        ON CONFLICT (user_id, assignment_id) DO NOTHING;
    END LOOP;

    INSERT INTO public.notifications (user_id, classroom_id, title, message, type)
    VALUES (
        v_req.user_id,
        v_req.classroom_id,
        'Join Request Approved!',
        'You have been approved to join ' || v_req.classroom_name || '. You can now access classroom assignments and discussions.',
        'request_approved'
    );

    RETURN jsonb_build_object(
        'success', true,
        'message', 'Student approved and added to classroom.'
    );
END;
$$;

-- 9. reject_join_request
CREATE OR REPLACE FUNCTION public.reject_join_request(
    p_request_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id UUID;
    v_req RECORD;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    SELECT r.*, c.name AS classroom_name, c.owner_id
    INTO v_req
    FROM public.classroom_join_requests r
    JOIN public.classrooms c ON c.id = r.classroom_id
    WHERE r.id = p_request_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Join request not found.';
    END IF;

    IF v_req.owner_id != v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: Only the designated classroom owner can reject join requests.';
    END IF;

    UPDATE public.classroom_join_requests
    SET status = 'rejected', reviewed_at = timezone('utc'::text, now()), reviewed_by = v_user_id
    WHERE id = p_request_id;

    INSERT INTO public.notifications (user_id, classroom_id, title, message, type)
    VALUES (
        v_req.user_id,
        v_req.classroom_id,
        'Join Request Decision',
        'Your request to join ' || v_req.classroom_name || ' was not approved by the classroom owner.',
        'request_rejected'
    );

    RETURN jsonb_build_object('success', true, 'message', 'Join request rejected.');
END;
$$;

-- 10. remove_classroom_member
CREATE OR REPLACE FUNCTION public.remove_classroom_member(
    p_classroom_id UUID,
    p_member_user_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id UUID;
    v_owner_id UUID;
    v_classroom_name TEXT;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    SELECT owner_id, name INTO v_owner_id, v_classroom_name
    FROM public.classrooms
    WHERE id = p_classroom_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Classroom not found.';
    END IF;

    IF v_owner_id != v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: Only the classroom owner can remove members.';
    END IF;

    IF p_member_user_id = v_owner_id THEN
        RAISE EXCEPTION 'Cannot remove the classroom owner. Use ownership transfer instead.';
    END IF;

    DELETE FROM public.classroom_members
    WHERE classroom_id = p_classroom_id AND user_id = p_member_user_id;

    DELETE FROM public.classroom_join_requests
    WHERE classroom_id = p_classroom_id AND user_id = p_member_user_id;

    DELETE FROM public.user_tasks
    WHERE classroom_id = p_classroom_id AND user_id = p_member_user_id;

    INSERT INTO public.notifications (user_id, classroom_id, title, message, type)
    VALUES (
        p_member_user_id,
        p_classroom_id,
        'Classroom Membership Removed',
        'You have been removed from ' || v_classroom_name || ' by the owner.',
        'member_removed'
    );

    RETURN jsonb_build_object('success', true, 'message', 'Member removed successfully.');
END;
$$;

-- 11. transfer_classroom_ownership
CREATE OR REPLACE FUNCTION public.transfer_classroom_ownership(
    p_classroom_id UUID,
    p_new_owner_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id UUID;
    v_owner_id UUID;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    SELECT owner_id INTO v_owner_id
    FROM public.classrooms
    WHERE id = p_classroom_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Classroom not found.';
    END IF;

    IF v_owner_id != v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: Only the current classroom owner can transfer ownership.';
    END IF;

    IF NOT public.is_approved_member(p_classroom_id, p_new_owner_id) THEN
        RAISE EXCEPTION 'New owner must already be an approved member of the classroom.';
    END IF;

    UPDATE public.classrooms
    SET owner_id = p_new_owner_id, updated_at = timezone('utc'::text, now())
    WHERE id = p_classroom_id;

    UPDATE public.classroom_members
    SET role = 'member'
    WHERE classroom_id = p_classroom_id AND user_id = v_user_id;

    UPDATE public.classroom_members
    SET role = 'owner'
    WHERE classroom_id = p_classroom_id AND user_id = p_new_owner_id;

    INSERT INTO public.notifications (user_id, classroom_id, title, message, type)
    VALUES (
        p_new_owner_id,
        p_classroom_id,
        'Classroom Ownership Transferred',
        'You are now the designated owner of this classroom.',
        'announcement'
    );

    RETURN jsonb_build_object('success', true, 'message', 'Ownership transferred successfully.');
END;
$$;

-- ----------------------------------------------------------------------------
-- SECTION 6: LEAST-PRIVILEGE SCHEMA, TABLE & FUNCTION PERMISSIONS
-- ----------------------------------------------------------------------------

-- 1. Grant schema usage to PostgREST API roles
GRANT USAGE ON SCHEMA public TO anon, authenticated;

-- 2. Explicitly revoke public execution from application RPCs ONLY.
-- (Prevents breaking PostgreSQL built-in or extension functions like gen_random_uuid/digest)
REVOKE EXECUTE ON FUNCTION public.get_invitation_preview(TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.is_approved_member(UUID, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.is_classroom_owner(UUID, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.create_classroom(TEXT, TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.create_invitation_link(UUID, TEXT, TIMESTAMPTZ) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.revoke_invitation_link(UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.request_to_join(TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.approve_join_request(UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.reject_join_request(UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.remove_classroom_member(UUID, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.transfer_classroom_ownership(UUID, UUID) FROM PUBLIC;

-- 3. Table Permissions: Authenticated users operate strictly under Row Level Security
GRANT SELECT, INSERT, UPDATE, DELETE ON public.profiles TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.classrooms TO authenticated;
GRANT SELECT, DELETE ON public.classroom_members TO authenticated;
GRANT SELECT ON public.classroom_invitations TO authenticated;
GRANT SELECT, UPDATE ON public.classroom_join_requests TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.classroom_posts TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.assignments TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.user_tasks TO authenticated;
GRANT SELECT, UPDATE ON public.notifications TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.notification_preferences TO authenticated;

-- 4. Explicit Function EXECUTE Grants:
-- Public preview is granted to anon (unauthenticated visitors) and authenticated students
GRANT EXECUTE ON FUNCTION public.get_invitation_preview(TEXT) TO anon, authenticated;

-- Protected RPCs are granted exclusively to authenticated users
GRANT EXECUTE ON FUNCTION public.is_approved_member(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_classroom_owner(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.create_classroom(TEXT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.create_invitation_link(UUID, TEXT, TIMESTAMPTZ) TO authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_invitation_link(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.request_to_join(TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.approve_join_request(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.reject_join_request(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.remove_classroom_member(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.transfer_classroom_ownership(UUID, UUID) TO authenticated;
