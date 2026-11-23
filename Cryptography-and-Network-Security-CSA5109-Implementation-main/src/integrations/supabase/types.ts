export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5";
  };
  public: {
    Tables: {
      app_sessions: {
        Row: {
          created_at: string;
          device_fingerprint: string | null;
          expires_at: string;
          id: string;
          ip_address: string | null;
          last_active: string;
          revoked: boolean;
          revoked_reason: string | null;
          user_agent: string | null;
          user_id: string;
        };
        Insert: {
          created_at?: string;
          device_fingerprint?: string | null;
          expires_at?: string;
          id?: string;
          ip_address?: string | null;
          last_active?: string;
          revoked?: boolean;
          revoked_reason?: string | null;
          user_agent?: string | null;
          user_id: string;
        };
        Update: {
          created_at?: string;
          device_fingerprint?: string | null;
          expires_at?: string;
          id?: string;
          ip_address?: string | null;
          last_active?: string;
          revoked?: boolean;
          revoked_reason?: string | null;
          user_agent?: string | null;
          user_id?: string;
        };
        Relationships: [];
      };
      audit_logs: {
        Row: {
          action: string | null;
          created_at: string;
          event: string;
          id: string;
          ip_address: string | null;
          metadata: Json;
          severity: string;
          transfer_id: string | null;
          user_id: string | null;
        };
        Insert: {
          action?: string | null;
          created_at?: string;
          event: string;
          id?: string;
          ip_address?: string | null;
          metadata?: Json;
          severity?: string;
          transfer_id?: string | null;
          user_id?: string | null;
        };
        Update: {
          action?: string | null;
          created_at?: string;
          event?: string;
          id?: string;
          ip_address?: string | null;
          metadata?: Json;
          severity?: string;
          transfer_id?: string | null;
          user_id?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "audit_logs_transfer_id_fkey";
            columns: ["transfer_id"];
            isOneToOne: false;
            referencedRelation: "transfers";
            referencedColumns: ["id"];
          },
        ];
      };
      devices: {
        Row: {
          fingerprint: string;
          first_seen: string;
          id: string;
          last_seen: string;
          trusted: boolean;
          user_agent: string | null;
          user_id: string;
        };
        Insert: {
          fingerprint: string;
          first_seen?: string;
          id?: string;
          last_seen?: string;
          trusted?: boolean;
          user_agent?: string | null;
          user_id: string;
        };
        Update: {
          fingerprint?: string;
          first_seen?: string;
          id?: string;
          last_seen?: string;
          trusted?: boolean;
          user_agent?: string | null;
          user_id?: string;
        };
        Relationships: [];
      };
      file_metadata: {
        Row: {
          created_at: string;
          extension: string | null;
          hash_algorithm: string;
          id: string;
          mime_type: string;
          original_name: string;
          size_bytes: number;
          transfer_id: string;
        };
        Insert: {
          created_at?: string;
          extension?: string | null;
          hash_algorithm?: string;
          id?: string;
          mime_type: string;
          original_name: string;
          size_bytes: number;
          transfer_id: string;
        };
        Update: {
          created_at?: string;
          extension?: string | null;
          hash_algorithm?: string;
          id?: string;
          mime_type?: string;
          original_name?: string;
          size_bytes?: number;
          transfer_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "file_metadata_transfer_id_fkey";
            columns: ["transfer_id"];
            isOneToOne: true;
            referencedRelation: "transfers";
            referencedColumns: ["id"];
          },
        ];
      };
      notifications: {
        Row: {
          body: string;
          created_at: string;
          id: string;
          read: boolean;
          severity: string;
          title: string;
          transfer_id: string | null;
          user_id: string;
        };
        Insert: {
          body: string;
          created_at?: string;
          id?: string;
          read?: boolean;
          severity?: string;
          title: string;
          transfer_id?: string | null;
          user_id: string;
        };
        Update: {
          body?: string;
          created_at?: string;
          id?: string;
          read?: boolean;
          severity?: string;
          title?: string;
          transfer_id?: string | null;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "notifications_transfer_id_fkey";
            columns: ["transfer_id"];
            isOneToOne: false;
            referencedRelation: "transfers";
            referencedColumns: ["id"];
          },
        ];
      };
      profiles: {
        Row: {
          created_at: string;
          email: string;
          full_name: string | null;
          id: string;
          organization: string | null;
          status: string;
          trust_score: number;
          trust_status: string;
          trust_updated_at: string;
          updated_at: string;
        };
        Insert: {
          created_at?: string;
          email: string;
          full_name?: string | null;
          id: string;
          organization?: string | null;
          status?: string;
          trust_score?: number;
          trust_status?: string;
          trust_updated_at?: string;
          updated_at?: string;
        };
        Update: {
          created_at?: string;
          email?: string;
          full_name?: string | null;
          id?: string;
          organization?: string | null;
          status?: string;
          trust_score?: number;
          trust_status?: string;
          trust_updated_at?: string;
          updated_at?: string;
        };
        Relationships: [];
      };
      security_events: {
        Row: {
          created_at: string;
          event_type: string;
          id: string;
          ip_address: string | null;
          metadata: Json;
          severity: string;
          simulated: boolean;
          transfer_id: string | null;
          trust_delta: number;
          user_id: string | null;
        };
        Insert: {
          created_at?: string;
          event_type: string;
          id?: string;
          ip_address?: string | null;
          metadata?: Json;
          severity?: string;
          simulated?: boolean;
          transfer_id?: string | null;
          trust_delta?: number;
          user_id?: string | null;
        };
        Update: {
          created_at?: string;
          event_type?: string;
          id?: string;
          ip_address?: string | null;
          metadata?: Json;
          severity?: string;
          simulated?: boolean;
          transfer_id?: string | null;
          trust_delta?: number;
          user_id?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "security_events_transfer_id_fkey";
            columns: ["transfer_id"];
            isOneToOne: false;
            referencedRelation: "transfers";
            referencedColumns: ["id"];
          },
        ];
      };
      threat_incidents: {
        Row: {
          action_taken: string;
          blocked: boolean;
          created_at: string;
          details: Json;
          id: string;
          resolved: boolean;
          severity: string;
          simulated: boolean;
          threat_type: string;
          transfer_id: string | null;
          trust_delta: number;
          user_id: string | null;
        };
        Insert: {
          action_taken: string;
          blocked?: boolean;
          created_at?: string;
          details?: Json;
          id?: string;
          resolved?: boolean;
          severity: string;
          simulated?: boolean;
          threat_type: string;
          transfer_id?: string | null;
          trust_delta?: number;
          user_id?: string | null;
        };
        Update: {
          action_taken?: string;
          blocked?: boolean;
          created_at?: string;
          details?: Json;
          id?: string;
          resolved?: boolean;
          severity?: string;
          simulated?: boolean;
          threat_type?: string;
          transfer_id?: string | null;
          trust_delta?: number;
          user_id?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "threat_incidents_transfer_id_fkey";
            columns: ["transfer_id"];
            isOneToOne: false;
            referencedRelation: "transfers";
            referencedColumns: ["id"];
          },
        ];
      };
      transfer_keys: {
        Row: {
          created_at: string;
          id: string;
          transfer_id: string;
          wrap_algorithm: string;
          wrapped_key: string;
        };
        Insert: {
          created_at?: string;
          id?: string;
          transfer_id: string;
          wrap_algorithm?: string;
          wrapped_key: string;
        };
        Update: {
          created_at?: string;
          id?: string;
          transfer_id?: string;
          wrap_algorithm?: string;
          wrapped_key?: string;
        };
        Relationships: [
          {
            foreignKeyName: "transfer_keys_transfer_id_fkey";
            columns: ["transfer_id"];
            isOneToOne: true;
            referencedRelation: "transfers";
            referencedColumns: ["id"];
          },
        ];
      };
      transfers: {
        Row: {
          ciphertext_sha256: string;
          created_at: string;
          download_count: number;
          expires_at: string;
          failed_attempts: number;
          id: string;
          iv: string;
          max_downloads: number;
          metrics: Json;
          original_sha256: string;
          receiver_latitude: number | null;
          receiver_location_timestamp: string | null;
          receiver_longitude: number | null;
          recipient_id: string;
          security_level: string;
          sender_id: string;
          sender_latitude: number | null;
          sender_location_timestamp: string | null;
          sender_longitude: number | null;
          sender_token_wrapped: string | null;
          status: string;
          storage_path: string | null;
          terminated_reason: string | null;
          token_hash: string;
          token_used_at: string | null;
          updated_at: string;
        };
        Insert: {
          ciphertext_sha256: string;
          created_at?: string;
          download_count?: number;
          expires_at: string;
          failed_attempts?: number;
          id?: string;
          iv: string;
          max_downloads?: number;
          metrics?: Json;
          original_sha256: string;
          receiver_latitude?: number | null;
          receiver_location_timestamp?: string | null;
          receiver_longitude?: number | null;
          recipient_id: string;
          security_level?: string;
          sender_id: string;
          sender_latitude?: number | null;
          sender_location_timestamp?: string | null;
          sender_longitude?: number | null;
          sender_token_wrapped?: string | null;
          status?: string;
          storage_path?: string | null;
          terminated_reason?: string | null;
          token_hash: string;
          token_used_at?: string | null;
          updated_at?: string;
        };
        Update: {
          ciphertext_sha256?: string;
          created_at?: string;
          download_count?: number;
          expires_at?: string;
          failed_attempts?: number;
          id?: string;
          iv?: string;
          max_downloads?: number;
          metrics?: Json;
          original_sha256?: string;
          receiver_latitude?: number | null;
          receiver_location_timestamp?: string | null;
          receiver_longitude?: number | null;
          recipient_id?: string;
          security_level?: string;
          sender_id?: string;
          sender_latitude?: number | null;
          sender_location_timestamp?: string | null;
          sender_longitude?: number | null;
          sender_token_wrapped?: string | null;
          status?: string;
          storage_path?: string | null;
          terminated_reason?: string | null;
          token_hash?: string;
          token_used_at?: string | null;
          updated_at?: string;
        };
        Relationships: [];
      };
      trust_events: {
        Row: {
          created_at: string;
          delta: number;
          id: string;
          new_score: number;
          previous_score: number;
          reason: string;
          security_event_id: string | null;
          user_id: string;
        };
        Insert: {
          created_at?: string;
          delta: number;
          id?: string;
          new_score: number;
          previous_score: number;
          reason: string;
          security_event_id?: string | null;
          user_id: string;
        };
        Update: {
          created_at?: string;
          delta?: number;
          id?: string;
          new_score?: number;
          previous_score?: number;
          reason?: string;
          security_event_id?: string | null;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "trust_events_security_event_id_fkey";
            columns: ["security_event_id"];
            isOneToOne: false;
            referencedRelation: "security_events";
            referencedColumns: ["id"];
          },
        ];
      };
      user_keys: {
        Row: {
          algorithm: string;
          created_at: string;
          id: string;
          kdf_salt: string;
          public_key_jwk: Json;
          user_id: string;
          wrap_iv: string;
          wrapped_private_key: string;
        };
        Insert: {
          algorithm?: string;
          created_at?: string;
          id?: string;
          kdf_salt: string;
          public_key_jwk: Json;
          user_id: string;
          wrap_iv: string;
          wrapped_private_key: string;
        };
        Update: {
          algorithm?: string;
          created_at?: string;
          id?: string;
          kdf_salt?: string;
          public_key_jwk?: Json;
          user_id?: string;
          wrap_iv?: string;
          wrapped_private_key?: string;
        };
        Relationships: [];
      };
      user_roles: {
        Row: {
          created_at: string;
          id: string;
          role: Database["public"]["Enums"]["app_role"];
          user_id: string;
        };
        Insert: {
          created_at?: string;
          id?: string;
          role: Database["public"]["Enums"]["app_role"];
          user_id: string;
        };
        Update: {
          created_at?: string;
          id?: string;
          role?: Database["public"]["Enums"]["app_role"];
          user_id?: string;
        };
        Relationships: [];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      get_public_key: { Args: { _user_id: string }; Returns: Json };
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"];
          _user_id: string;
        };
        Returns: boolean;
      };
      users_with_published_keys: {
        Args: never;
        Returns: {
          user_id: string;
        }[];
      };
    };
    Enums: {
      app_role: "admin" | "user";
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
};

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">;

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">];

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R;
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] & DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R;
      }
      ? R
      : never
    : never;

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I;
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I;
      }
      ? I
      : never
    : never;

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U;
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U;
      }
      ? U
      : never
    : never;

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    keyof DefaultSchema["Enums"] | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never;

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    keyof DefaultSchema["CompositeTypes"] | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never;

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "user"],
    },
  },
} as const;
