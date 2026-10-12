-- ============================================================================
-- CAMPUSMATE DATABASE SCHEMA & SECURITY POLICIES (SUPABASE POSTGRESQL)
-- ============================================================================
-- Features:
-- 1. Profiles with Full Name, College Email, Roll Number (Strictly 3 fields)
-- 2. Classrooms with strict single-owner model
-- 3. Secure Invitations with SHA-256 token hashing, expiration, and revocation
-- 4. Classroom Join Requests with owner-only approval/rejection
-- 5. Classroom Members with OWNER and MEMBER roles
-- 6. Zero-trust Row Level Security (RLS) on all tables
-- 7. PostgreSQL SECURITY DEFINER RPC functions for atomic, verified workflows
-- 8. Integrated Assignments, Timeline Posts, User Tasks, and Notifications
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. PROFILES TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL CHECK (char_length(trim(full_name)) > 0),
    college_email TEXT NOT NULL UNIQUE CHECK (college_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    roll_number TEXT NOT NULL CHECK (char_length(trim(roll_number)) > 0),
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Index for searching profiles
CREATE INDEX IF NOT EXISTS idx_profiles_college_email ON public.profiles(college_email);
CREATE INDEX IF NOT EXISTS idx_profiles_roll_number ON public.profiles(roll_number);

-- Enable RLS on profiles
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Profiles Policies
CREATE POLICY "Profiles are viewable by authenticated users"
    ON public.profiles FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Users can insert their own profile"
    ON public.profiles FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() = id);

CREATE POLICY "Users can update their own profile"
    ON public.profiles FOR UPDATE
    TO authenticated
    USING (auth.uid() = id);

-- ----------------------------------------------------------------------------
-- 2. CLASSROOMS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.classrooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (char_length(trim(name)) > 0),
    description TEXT DEFAULT '',
    owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_classrooms_owner_id ON public.classrooms(owner_id);

ALTER TABLE public.classrooms ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 3. CLASSROOM MEMBERS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.classroom_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    classroom_id UUID NOT NULL REFERENCES public.classrooms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    membership_status TEXT NOT NULL CHECK (membership_status IN ('approved', 'removed')),
    joined_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT unique_classroom_user UNIQUE (classroom_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_classroom_members_cid_uid ON public.classroom_members(classroom_id, user_id);
CREATE INDEX IF NOT EXISTS idx_classroom_members_user_id ON public.classroom_members(user_id);

ALTER TABLE public.classroom_members ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 4. CLASSROOM INVITATIONS TABLE (Stored with Token Hashes)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.classroom_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    classroom_id UUID NOT NULL REFERENCES public.classrooms(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_by UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON public.classroom_invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_invitations_classroom_id ON public.classroom_invitations(classroom_id);

ALTER TABLE public.classroom_invitations ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 5. CLASSROOM JOIN REQUESTS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.classroom_join_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    classroom_id UUID NOT NULL REFERENCES public.classrooms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    requested_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    reviewed_at TIMESTAMPTZ,
    reviewed_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    CONSTRAINT unique_classroom_join_request UNIQUE (classroom_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_join_requests_cid_status ON public.classroom_join_requests(classroom_id, status);
CREATE INDEX IF NOT EXISTS idx_join_requests_user_id ON public.classroom_join_requests(user_id);

ALTER TABLE public.classroom_join_requests ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 6. CLASSROOM POSTS / ANNOUNCEMENTS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.classroom_posts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    classroom_id UUID NOT NULL REFERENCES public.classrooms(id) ON DELETE CASCADE,
    author_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    title TEXT NOT NULL CHECK (char_length(trim(title)) > 0),
    content TEXT NOT NULL CHECK (char_length(trim(content)) > 0),
    is_faculty_verified BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_classroom_posts_classroom_id ON public.classroom_posts(classroom_id);

ALTER TABLE public.classroom_posts ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 7. ASSIGNMENTS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    classroom_id UUID NOT NULL REFERENCES public.classrooms(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    title TEXT NOT NULL CHECK (char_length(trim(title)) > 0),
    description TEXT DEFAULT '',
    subject TEXT NOT NULL CHECK (char_length(trim(subject)) > 0),
    due_date TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assignments_classroom_id ON public.assignments(classroom_id);
CREATE INDEX IF NOT EXISTS idx_assignments_due_date ON public.assignments(due_date);

ALTER TABLE public.assignments ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 8. USER TASKS (Personal Academic Schedule & Reminders)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.user_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    assignment_id UUID REFERENCES public.assignments(id) ON DELETE SET NULL,
    classroom_id UUID REFERENCES public.classrooms(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    due_date TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed')),
    reminder_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT unique_user_assignment_task UNIQUE (user_id, assignment_id)
);

CREATE INDEX IF NOT EXISTS idx_user_tasks_uid_status ON public.user_tasks(user_id, status);

ALTER TABLE public.user_tasks ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 9. NOTIFICATIONS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    classroom_id UUID REFERENCES public.classrooms(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('join_request', 'request_approved', 'request_rejected', 'assignment_shared', 'announcement', 'reminder', 'member_removed')),
    is_read BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON public.notifications(user_id, is_read);

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 10. NOTIFICATION PREFERENCES TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.notification_preferences (
    user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
    reminder_hours_before INT DEFAULT 24 CHECK (reminder_hours_before >= 1),
    email_notifications_enabled BOOLEAN DEFAULT true NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);

ALTER TABLE public.notification_preferences ENABLE ROW LEVEL SECURITY;


-- ============================================================================
-- ROW LEVEL SECURITY POLICIES (ZERO-TRUST AUTHORIZATION)
-- ============================================================================

-- Function to check if user is an approved member or owner of a classroom
CREATE OR REPLACE FUNCTION public.is_approved_member(p_classroom_id UUID, p_user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.classroom_members
        WHERE classroom_id = p_classroom_id
          AND user_id = p_user_id
          AND membership_status = 'approved'
    );
$$;

-- Function to check if user is the designated owner of a classroom
CREATE OR REPLACE FUNCTION public.is_classroom_owner(p_classroom_id UUID, p_user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.classrooms
        WHERE id = p_classroom_id
          AND owner_id = p_user_id
    );
$$;

-- CLASSROOMS POLICIES
CREATE POLICY "Classrooms are viewable by owner or approved members"
    ON public.classrooms FOR SELECT
    TO authenticated
    USING (
        owner_id = auth.uid() OR public.is_approved_member(id, auth.uid())
    );

CREATE POLICY "Authenticated users can create classrooms"
    ON public.classrooms FOR INSERT
    TO authenticated
    WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Only owner can update classroom details"
    ON public.classrooms FOR UPDATE
    TO authenticated
    USING (owner_id = auth.uid())
    WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Only owner can delete classroom"
    ON public.classrooms FOR DELETE
    TO authenticated
    USING (owner_id = auth.uid());

-- CLASSROOM MEMBERS POLICIES
CREATE POLICY "Members viewable only by approved members or owner"
    ON public.classroom_members FOR SELECT
    TO authenticated
    USING (
        public.is_approved_member(classroom_id, auth.uid())
        OR public.is_classroom_owner(classroom_id, auth.uid())
    );

-- Direct client inserts into classroom_members are BLOCKED (Must use RPC)
CREATE POLICY "No direct client inserts into classroom_members"
    ON public.classroom_members FOR INSERT
    TO authenticated
    WITH CHECK (false);

-- Direct client updates to roles are BLOCKED (Must use RPC)
CREATE POLICY "No direct client updates to classroom_members"
    ON public.classroom_members FOR UPDATE
    TO authenticated
    USING (false);

CREATE POLICY "Owners can remove members or members can leave"
    ON public.classroom_members FOR DELETE
    TO authenticated
    USING (
        public.is_classroom_owner(classroom_id, auth.uid())
        OR user_id = auth.uid()
    );

-- CLASSROOM INVITATIONS POLICIES
-- Raw invitation records viewable and manageable ONLY by the classroom owner
CREATE POLICY "Invitations manageable only by classroom owner"
    ON public.classroom_invitations FOR ALL
    TO authenticated
    USING (public.is_classroom_owner(classroom_id, auth.uid()))
    WITH CHECK (public.is_classroom_owner(classroom_id, auth.uid()));

-- CLASSROOM JOIN REQUESTS POLICIES
CREATE POLICY "Join requests viewable by classroom owner or the applicant"
    ON public.classroom_join_requests FOR SELECT
    TO authenticated
    USING (
        user_id = auth.uid()
        OR public.is_classroom_owner(classroom_id, auth.uid())
    );

CREATE POLICY "Applicants can cancel their own pending requests"
    ON public.classroom_join_requests FOR UPDATE
    TO authenticated
    USING (user_id = auth.uid() AND status = 'pending')
    WITH CHECK (user_id = auth.uid() AND status = 'cancelled');

-- CLASSROOM POSTS POLICIES
CREATE POLICY "Classroom posts viewable only by approved members or owner"
    ON public.classroom_posts FOR SELECT
    TO authenticated
    USING (
        public.is_approved_member(classroom_id, auth.uid())
        OR public.is_classroom_owner(classroom_id, auth.uid())
    );

CREATE POLICY "Approved members or owner can create posts"
    ON public.classroom_posts FOR INSERT
    TO authenticated
    WITH CHECK (
        author_id = auth.uid() AND (
            public.is_approved_member(classroom_id, auth.uid())
            OR public.is_classroom_owner(classroom_id, auth.uid())
        )
    );

-- ASSIGNMENTS POLICIES
CREATE POLICY "Assignments viewable only by approved members or owner"
    ON public.assignments FOR SELECT
    TO authenticated
    USING (
        public.is_approved_member(classroom_id, auth.uid())
        OR public.is_classroom_owner(classroom_id, auth.uid())
    );

CREATE POLICY "Approved members or owner can share assignments"
    ON public.assignments FOR INSERT
    TO authenticated
    WITH CHECK (
        created_by = auth.uid() AND (
            public.is_approved_member(classroom_id, auth.uid())
            OR public.is_classroom_owner(classroom_id, auth.uid())
        )
    );

-- USER TASKS POLICIES
CREATE POLICY "User tasks accessible only by the task owner"
    ON public.user_tasks FOR ALL
    TO authenticated
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

-- NOTIFICATIONS POLICIES
CREATE POLICY "Notifications accessible only by the recipient"
    ON public.notifications FOR ALL
    TO authenticated
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

-- NOTIFICATION PREFERENCES POLICIES
CREATE POLICY "Notification preferences accessible only by owner"
    ON public.notification_preferences FOR ALL
    TO authenticated
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());


-- ============================================================================
-- SECURE STORED PROCEDURES / RPC FUNCTIONS (SECURITY DEFINER)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- RPC: Create Classroom
-- Automatically registers owner in classroom_members and sets initial state
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.create_classroom(
    p_name TEXT,
    p_description TEXT DEFAULT ''
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
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

    -- Create classroom
    INSERT INTO public.classrooms (name, description, owner_id)
    VALUES (trim(p_name), trim(p_description), v_user_id)
    RETURNING id INTO v_classroom_id;

    -- Add owner to classroom_members
    INSERT INTO public.classroom_members (classroom_id, user_id, role, membership_status)
    VALUES (v_classroom_id, v_user_id, 'owner', 'approved');

    RETURN jsonb_build_object(
        'success', true,
        'classroom_id', v_classroom_id,
        'name', trim(p_name)
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- RPC: Create / Regenerate Invitation Link
-- Revokes any existing active invitation and creates a new one
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.create_invitation_link(
    p_classroom_id UUID,
    p_token_hash TEXT,
    p_expires_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
    v_invitation_id UUID;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    -- Verify owner authorization
    IF NOT public.is_classroom_owner(p_classroom_id, v_user_id) THEN
        RAISE EXCEPTION 'Access denied. Only the classroom owner can generate invitation links.';
    END IF;

    -- Revoke existing active invitations for this classroom
    UPDATE public.classroom_invitations
    SET revoked_at = timezone('utc'::text, now())
    WHERE classroom_id = p_classroom_id AND revoked_at IS NULL;

    -- Insert new invitation
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

-- ----------------------------------------------------------------------------
-- RPC: Revoke Invitation Link
-- Invalidate current invitation link without affecting approved members
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.revoke_invitation_link(
    p_classroom_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
BEGIN
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    -- Verify owner authorization
    IF NOT public.is_classroom_owner(p_classroom_id, v_user_id) THEN
        RAISE EXCEPTION 'Access denied. Only the classroom owner can revoke invitation links.';
    END IF;

    UPDATE public.classroom_invitations
    SET revoked_at = timezone('utc'::text, now())
    WHERE classroom_id = p_classroom_id AND revoked_at IS NULL;

    RETURN jsonb_build_object('success', true, 'message', 'Invitation link revoked.');
END;
$$;

-- ----------------------------------------------------------------------------
-- RPC: Get Limited Invitation Preview
-- Validates token and returns ONLY classroom name & owner name.
-- DOES NOT expose member list, assignments, or posts!
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.get_invitation_preview(
    p_token_hash TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
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

-- ----------------------------------------------------------------------------
-- RPC: Request to Join Classroom
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.request_to_join(
    p_token_hash TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
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

    -- Validate invitation
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

    -- Check if already approved member
    IF public.is_approved_member(v_classroom_id, v_user_id) THEN
        RETURN jsonb_build_object('success', false, 'message', 'You are already an approved member of this classroom.');
    END IF;

    -- Check existing request
    SELECT * INTO v_existing_req
    FROM public.classroom_join_requests
    WHERE classroom_id = v_classroom_id AND user_id = v_user_id;

    IF FOUND THEN
        IF v_existing_req.status = 'pending' THEN
            RETURN jsonb_build_object('success', true, 'status', 'pending', 'message', 'Your request is already pending approval.');
        ELSIF v_existing_req.status = 'approved' THEN
            RETURN jsonb_build_object('success', true, 'status', 'approved', 'message', 'Your request has already been approved.');
        ELSIF v_existing_req.status = 'rejected' THEN
            -- Re-requesting after rejection
            UPDATE public.classroom_join_requests
            SET status = 'pending', requested_at = timezone('utc'::text, now()), reviewed_at = NULL, reviewed_by = NULL
            WHERE id = v_existing_req.id;
        ELSIF v_existing_req.status = 'cancelled' THEN
            UPDATE public.classroom_join_requests
            SET status = 'pending', requested_at = timezone('utc'::text, now()), reviewed_at = NULL, reviewed_by = NULL
            WHERE id = v_existing_req.id;
        END IF;
    ELSE
        INSERT INTO public.classroom_join_requests (classroom_id, user_id, status)
        VALUES (v_classroom_id, v_user_id, 'pending');
    END IF;

    -- Fetch applicant name for owner notification
    SELECT full_name INTO v_applicant_name FROM public.profiles WHERE id = v_user_id;

    -- Notify classroom owner
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

-- ----------------------------------------------------------------------------
-- RPC: Approve Join Request (Owner Only)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.approve_join_request(
    p_request_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
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

    -- Fetch request
    SELECT r.*, c.name AS classroom_name, c.owner_id
    INTO v_req
    FROM public.classroom_join_requests r
    JOIN public.classrooms c ON c.id = r.classroom_id
    WHERE r.id = p_request_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Join request not found.';
    END IF;

    -- Strict server-side verification: ONLY the owner can approve
    IF v_req.owner_id != v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: Only the designated classroom owner can approve join requests.';
    END IF;

    -- 1. Update request status
    UPDATE public.classroom_join_requests
    SET status = 'approved', reviewed_at = timezone('utc'::text, now()), reviewed_by = v_user_id
    WHERE id = p_request_id;

    -- 2. Add or update classroom_members entry
    INSERT INTO public.classroom_members (classroom_id, user_id, role, membership_status, joined_at)
    VALUES (v_req.classroom_id, v_req.user_id, 'member', 'approved', timezone('utc'::text, now()))
    ON CONFLICT (classroom_id, user_id)
    DO UPDATE SET membership_status = 'approved', joined_at = timezone('utc'::text, now());

    -- 3. Populate upcoming active assignments into student's personal tasks (no obsolete/past tasks)
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

    -- 4. Notify the student
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

-- ----------------------------------------------------------------------------
-- RPC: Reject Join Request (Owner Only)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.reject_join_request(
    p_request_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
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

    -- Strict server-side verification: ONLY the owner can reject
    IF v_req.owner_id != v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: Only the designated classroom owner can reject join requests.';
    END IF;

    -- 1. Update request status
    UPDATE public.classroom_join_requests
    SET status = 'rejected', reviewed_at = timezone('utc'::text, now()), reviewed_by = v_user_id
    WHERE id = p_request_id;

    -- 2. Notify student
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

-- ----------------------------------------------------------------------------
-- RPC: Remove Member (Owner Only)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.remove_classroom_member(
    p_classroom_id UUID,
    p_member_user_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
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

    -- Remove from classroom_members
    DELETE FROM public.classroom_members
    WHERE classroom_id = p_classroom_id AND user_id = p_member_user_id;

    -- Remove join request or mark removed
    DELETE FROM public.classroom_join_requests
    WHERE classroom_id = p_classroom_id AND user_id = p_member_user_id;

    -- Notify the removed student
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

-- ----------------------------------------------------------------------------
-- RPC: Transfer Classroom Ownership (Owner Only)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.transfer_classroom_ownership(
    p_classroom_id UUID,
    p_new_owner_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
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

    -- Verify new owner is an approved member
    IF NOT public.is_approved_member(p_classroom_id, p_new_owner_id) THEN
        RAISE EXCEPTION 'New owner must already be an approved member of the classroom.';
    END IF;

    -- Update classroom owner
    UPDATE public.classrooms
    SET owner_id = p_new_owner_id, updated_at = timezone('utc'::text, now())
    WHERE id = p_classroom_id;

    -- Demote old owner to member
    UPDATE public.classroom_members
    SET role = 'member'
    WHERE classroom_id = p_classroom_id AND user_id = v_user_id;

    -- Promote new owner
    UPDATE public.classroom_members
    SET role = 'owner'
    WHERE classroom_id = p_classroom_id AND user_id = p_new_owner_id;

    -- Notify new owner
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
