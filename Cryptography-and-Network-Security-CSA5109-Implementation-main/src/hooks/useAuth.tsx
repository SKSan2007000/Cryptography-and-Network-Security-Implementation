import { useQueryClient } from "@tanstack/react-query";
import type { Session, User } from "@supabase/supabase-js";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { supabase } from "@/integrations/supabase/client";
import { deviceFingerprint } from "@/lib/crypto";
import { startSession, endSession } from "@/lib/sentinel.functions";

export type Profile = {
  id: string;
  email: string;
  full_name: string | null;
  organization: string | null;
  trust_score: number;
  status: string;
  created_at: string;
};

type SessionInfo = {
  sessionId: string | null;
  expiresAt: string | null;
  ip: string;
  threats: string[];
};

type AuthContextValue = {
  user: User | null;
  session: Session | null;
  profile: Profile | null;
  isAdmin: boolean;
  loading: boolean;
  sessionInfo: SessionInfo | null;
  refreshProfile: () => Promise<void>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [sessionInfo, setSessionInfo] = useState<SessionInfo | null>(null);
  const registered = useRef<string | null>(null);
  const queryClient = useQueryClient();

  const loadProfile = useCallback(async (uid: string) => {
    const [{ data: profileRow }, { data: roles }] = await Promise.all([
      supabase.from("profiles").select("*").eq("id", uid).maybeSingle(),
      supabase.from("user_roles").select("role").eq("user_id", uid),
    ]);
    setProfile((profileRow as Profile) ?? null);
    setIsAdmin((roles ?? []).some((r) => r.role === "admin"));
  }, []);

  useEffect(() => {
    const { data: sub } = supabase.auth.onAuthStateChange((event, next) => {
      setSession(next);
      setUser(next?.user ?? null);
      if (next?.user) {
        setTimeout(() => void loadProfile(next.user.id), 0);
      } else {
        setProfile(null);
        setIsAdmin(false);
        setSessionInfo(null);
        registered.current = null;
      }
      if (event === "SIGNED_OUT") queryClient.clear();
    });

    void supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setUser(data.session?.user ?? null);
      if (data.session?.user) void loadProfile(data.session.user.id);
      setLoading(false);
    });

    return () => sub.subscription.unsubscribe();
  }, [loadProfile, queryClient]);

  // Establish the monitored application session exactly once per auth session.
  useEffect(() => {
    if (!user || registered.current === user.id) return;
    registered.current = user.id;
    void startSession({ data: { deviceFingerprint: deviceFingerprint() } })
      .then((info) => {
        setSessionInfo(info);
        void loadProfile(user.id);
      })
      .catch(() => {
        registered.current = null;
      });
  }, [user, loadProfile]);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      session,
      profile,
      isAdmin,
      loading,
      sessionInfo,
      refreshProfile: async () => {
        if (user) await loadProfile(user.id);
      },
      signOut: async () => {
        try {
          await endSession();
        } catch {
          /* session already closed */
        }
        sessionStorage.removeItem("sc_key_passphrase");
        await supabase.auth.signOut();
      },
    }),
    [user, session, profile, isAdmin, loading, sessionInfo, loadProfile],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
