/**
 * SentinelCrypt Centralized FastAPI Client
 *
 * Replaces Supabase runtime dependency with direct, authenticated REST API
 * communication to the Python FastAPI backend powered by PostgreSQL.
 */

const TOKEN_KEY = "sentinelcrypt_jwt_token";
const SESSION_DATA_KEY = "sentinelcrypt_user_session";

export interface ApiUser {
  id: string;
  email: string;
  is_active: boolean;
  profile?: {
    id: string;
    email: string;
    full_name?: string | null;
    organization?: string | null;
    trust_score: number;
    trust_status: string;
    status: string;
  } | null;
  roles: string[];
}

export interface ApiAuthResponse {
  access_token: string;
  token_type: string;
  user: ApiUser;
}

export interface ApiTransfer {
  id: string;
  sender_id: string;
  recipient_id: string;
  status: string;
  security_level: string;
  storage_path?: string | null;
  iv: string;
  original_sha256: string;
  ciphertext_sha256: string;
  expires_at: string;
  max_downloads: number;
  download_count: number;
  failed_attempts: number;
  terminated_reason?: string | null;
  sender_latitude?: number | null;
  sender_longitude?: number | null;
  receiver_latitude?: number | null;
  receiver_longitude?: number | null;
  created_at: string;
  updated_at: string;
  file_metadata?: {
    id: string;
    original_name: string;
    mime_type: string;
    size_bytes: number;
    extension?: string | null;
    hash_algorithm: string;
  } | null;
  transfer_key?: {
    wrapped_key: string;
    wrap_algorithm: string;
  } | null;
  sender_email?: string | null;
  recipient_email?: string | null;
}

class ApiClient {
  private inMemoryToken: string | null = null;
  private inMemoryUser: ApiUser | null = null;

  private getBaseUrl(): string {
    if (typeof window !== "undefined") {
      // In browser, if VITE_API_URL is configured use it, else default to backend on 8000 or relative /api
      const envUrl = (import.meta as unknown as { env: Record<string, string> }).env?.[
        "VITE_API_URL"
      ];
      return envUrl || "http://127.0.0.1:8000";
    }
    return process.env["API_URL"] || "http://127.0.0.1:8000";
  }

  public getToken(): string | null {
    if (this.inMemoryToken) return this.inMemoryToken;
    if (typeof window === "undefined") return null;
    return localStorage.getItem(TOKEN_KEY);
  }

  public setSession(token: string, user: ApiUser) {
    this.inMemoryToken = token;
    this.inMemoryUser = user;
    if (typeof window === "undefined") return;
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(SESSION_DATA_KEY, JSON.stringify(user));
  }

  public clearSession() {
    this.inMemoryToken = null;
    this.inMemoryUser = null;
    if (typeof window === "undefined") return;
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(SESSION_DATA_KEY);
  }

  public getStoredUser(): ApiUser | null {
    if (this.inMemoryUser) return this.inMemoryUser;
    if (typeof window === "undefined") return null;
    const raw = localStorage.getItem(SESSION_DATA_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const baseUrl = this.getBaseUrl();
    const url = `${baseUrl}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;
    const token = this.getToken();

    const headers = new Headers(options.headers || {});
    if (!headers.has("Content-Type") && !(options.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    if (token && !headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${token}`);
    }

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          errorMessage =
            typeof errorJson.detail === "string"
              ? errorJson.detail
              : JSON.stringify(errorJson.detail);
        } else if (errorJson.message) {
          errorMessage = errorJson.message;
        }
      } catch {
        // use fallback message
      }
      throw new Error(errorMessage);
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return null as unknown as T;
    }

    const contentType = response.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      return response.json();
    }
    return response.text() as unknown as T;
  }

  // ---------------- Authentication ----------------
  public async register(payload: {
    email: string;
    password: string;
    full_name?: string | null;
    organization?: string | null;
  }): Promise<ApiAuthResponse> {
    const res = await this.request<ApiAuthResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    this.setSession(res.access_token, res.user);
    return res;
  }

  public async login(payload: { email: string; password: string }): Promise<ApiAuthResponse> {
    const res = await this.request<ApiAuthResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    this.setSession(res.access_token, res.user);
    return res;
  }

  public async logout(): Promise<void> {
    try {
      await this.request("/api/auth/logout", { method: "POST" });
    } catch {
      // Ignore network errors on logout
    } finally {
      this.clearSession();
    }
  }

  public async getMe(): Promise<ApiUser> {
    const user = await this.request<ApiUser>("/api/auth/me", { method: "GET" });
    if (typeof window !== "undefined") {
      localStorage.setItem(SESSION_DATA_KEY, JSON.stringify(user));
    }
    return user;
  }

  public async getSessionStatus(): Promise<{
    authenticated: boolean;
    user_id?: string;
    email?: string;
    trust_score?: number;
  }> {
    return this.request("/api/auth/session", { method: "GET" });
  }

  // ---------------- Users & Cryptographic Keys ----------------
  public async listRecipients(query?: string): Promise<
    Array<{
      id: string;
      email: string;
      full_name?: string | null;
      organization?: string | null;
      trust_score: number;
      trust_status: string;
    }>
  > {
    const params = query ? `?query=${encodeURIComponent(query)}` : "";
    return this.request(`/api/users${params}`, { method: "GET" });
  }

  public async getPublicKey(
    userId: string,
  ): Promise<{ user_id: string; public_key_jwk: JsonWebKey }> {
    return this.request(`/api/users/${userId}/public-key`, { method: "GET" });
  }

  public async registerKeys(payload: {
    public_key_jwk: JsonWebKey;
    wrapped_private_key: string;
    kdf_salt: string;
    wrap_iv: string;
    algorithm?: string;
  }): Promise<unknown> {
    return this.request("/api/users/keys", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  public async getMyKeys(): Promise<{
    id: string;
    user_id: string;
    public_key_jwk: JsonWebKey;
    wrapped_private_key: string;
    kdf_salt: string;
    wrap_iv: string;
    algorithm: string;
  }> {
    return this.request("/api/users/keys/me", { method: "GET" });
  }

  public async updateProfile(payload: {
    full_name?: string;
    organization?: string;
  }): Promise<unknown> {
    return this.request("/api/users/profile", {
      method: "PUT",
      body: JSON.stringify(payload),
    });
  }

  // ---------------- Transfers ----------------
  public async createTransfer(payload: {
    recipient_id: string;
    security_level?: string;
    iv: string;
    original_sha256: string;
    ciphertext_sha256: string;
    token_hash: string;
    expires_at: string;
    max_downloads?: number;
    wrapped_key: string;
    wrap_algorithm?: string;
    file_name: string;
    file_size: number;
    mime_type?: string;
    extension?: string;
    sender_token_wrapped?: string;
    sender_latitude?: number | null;
    sender_longitude?: number | null;
    sender_location_accuracy?: number | null;
  }): Promise<ApiTransfer> {
    return this.request<ApiTransfer>("/api/transfers", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  public async uploadPayload(
    transferId: string,
    data: Blob | Uint8Array,
    fileName: string,
  ): Promise<{ message: string; storage_path: string }> {
    const formData = new FormData();
    const blob =
      data instanceof Blob
        ? data
        : new Blob([data as unknown as ArrayBuffer], { type: "application/octet-stream" });
    formData.append("file", blob, fileName);

    const baseUrl = this.getBaseUrl();
    const token = this.getToken();
    const response = await fetch(`${baseUrl}/api/transfers/${transferId}/upload`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(err.detail || "Failed to upload encrypted payload");
    }
    return response.json();
  }

  public async listTransfers(filter?: "inbox" | "sent"): Promise<ApiTransfer[]> {
    const params = filter ? `?filter=${filter}` : "";
    return this.request<ApiTransfer[]>(`/api/transfers${params}`, { method: "GET" });
  }

  public async getTransferDetail(transferId: string): Promise<ApiTransfer> {
    return this.request<ApiTransfer>(`/api/transfers/${transferId}`, { method: "GET" });
  }

  public async downloadPayload(transferId: string): Promise<Uint8Array> {
    const baseUrl = this.getBaseUrl();
    const token = this.getToken();
    const response = await fetch(`${baseUrl}/api/transfers/${transferId}/download`, {
      method: "GET",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(err.detail || "Failed to download encrypted payload");
    }

    const buffer = await response.arrayBuffer();
    return new Uint8Array(buffer);
  }

  public async completeTransfer(transferId: string): Promise<{ message: string }> {
    return this.request(`/api/transfers/${transferId}/complete`, { method: "POST" });
  }

  public async failTransfer(
    transferId: string,
    reason: string,
    isTampered: boolean = false,
  ): Promise<{ message: string }> {
    return this.request(`/api/transfers/${transferId}/fail`, {
      method: "POST",
      body: JSON.stringify({ reason, is_tampered: isTampered }),
    });
  }

  public async revokeTransfer(transferId: string): Promise<{ message: string }> {
    return this.request(`/api/transfers/${transferId}/revoke`, { method: "POST" });
  }

  // ---------------- Security & Trust ----------------
  public async recordSecurityEvent(payload: {
    event_type: string;
    severity?: string;
    transfer_id?: string;
    trust_delta?: number;
    simulated?: boolean;
    metadata?: Record<string, unknown>;
  }): Promise<unknown> {
    return this.request("/api/security/events", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  public async listSecurityEvents(limit: number = 50): Promise<unknown[]> {
    return this.request(`/api/security/events?limit=${limit}`, { method: "GET" });
  }

  public async listThreatIncidents(limit: number = 50): Promise<unknown[]> {
    return this.request(`/api/security/threats?limit=${limit}`, { method: "GET" });
  }

  public async resolveThreatIncident(incidentId: string): Promise<{ message: string }> {
    return this.request(`/api/security/threats/${incidentId}/resolve`, { method: "POST" });
  }

  public async getTrustEvents(): Promise<unknown[]> {
    return this.request("/api/trust/events", { method: "GET" });
  }

  // ---------------- Digital Twin & Location ----------------
  public async updateLocation(payload: {
    latitude: number;
    longitude: number;
    accuracy?: number;
  }): Promise<unknown> {
    return this.request("/api/digital-twin/location", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  public async getDigitalTwinNodes(): Promise<
    Array<{
      id: string;
      label: string;
      type: string;
      latitude: number;
      longitude: number;
      trust_score: number;
      status: string;
    }>
  > {
    return this.request("/api/digital-twin/nodes", { method: "GET" });
  }

  public async getTwinTelemetry(): Promise<Record<string, unknown>> {
    return this.request("/api/digital-twin/telemetry", { method: "GET" });
  }

  // ---------------- Security Lab ----------------
  public async runLabSimulation(payload: {
    scenario: string;
    transfer_id?: string;
  }): Promise<Record<string, unknown>> {
    return this.request("/api/security-lab/simulate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  public async getLabStatus(): Promise<Record<string, unknown>> {
    return this.request("/api/security-lab/status", { method: "GET" });
  }

  // ---------------- Notifications ----------------
  public async listNotifications(limit: number = 20): Promise<unknown[]> {
    return this.request(`/api/notifications?limit=${limit}`, { method: "GET" });
  }

  public async markNotificationRead(id: string): Promise<{ message: string }> {
    return this.request(`/api/notifications/${id}/read`, { method: "PUT" });
  }

  // ---------------- Administration ----------------
  public async getAdminUsers(): Promise<ApiUser[]> {
    return this.request<ApiUser[]>("/api/admin/users", { method: "GET" });
  }

  public async updateAdminUserRole(userId: string, role: string): Promise<{ message: string }> {
    return this.request(`/api/admin/users/${userId}/role`, {
      method: "PUT",
      body: JSON.stringify({ role }),
    });
  }

  public async updateAdminUserStatus(
    userId: string,
    isActive: boolean,
  ): Promise<{ message: string }> {
    return this.request(`/api/admin/users/${userId}/status`, {
      method: "PUT",
      body: JSON.stringify({ is_active: isActive }),
    });
  }

  public async getAuditLogs(limit: number = 100): Promise<unknown[]> {
    return this.request(`/api/admin/audit-logs?limit=${limit}`, { method: "GET" });
  }
}

export const apiClient = new ApiClient();
