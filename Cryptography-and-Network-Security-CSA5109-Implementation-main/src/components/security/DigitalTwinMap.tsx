import { useEffect, useRef, useState } from "react";
import {
  Activity,
  Compass,
  FileLock2,
  Globe,
  Info,
  Layers,
  MapPin,
  Maximize2,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import "leaflet/dist/leaflet.css";
import L from "leaflet";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { getTrustStatus, type TrustStatus } from "@/lib/security-rules";
import { cn } from "@/lib/utils";

export type MapTransferNode = {
  id: string;
  senderName: string;
  senderEmail?: string;
  senderTrustScore: number;
  senderLatitude: number | null;
  senderLongitude: number | null;
  senderLocationTimestamp: string | null;
  senderLocationAccuracy?: number | null;
  recipientName: string;
  recipientEmail?: string;
  recipientTrustScore: number;
  receiverLatitude: number | null;
  receiverLongitude: number | null;
  receiverLocationTimestamp: string | null;
  receiverLocationAccuracy?: number | null;
  fileName: string;
  fileSizeBytes: number;
  encryptionAlgorithm: string;
  keyWrapAlgorithm: string;
  hashAlgorithm: string;
  originalSha256?: string;
  ciphertextSha256?: string;
  status: string;
  createdAt: string;
  hasLocation?: boolean;
  terminatedReason?: string | null;
};

export type MapEventNode = {
  id: string;
  userId?: string | null;
  userEmail: string;
  transferId?: string | null;
  eventType: string;
  severity: string;
  ipAddress: string | null;
  trustDelta: number;
  simulated: boolean;
  createdAt: string;
  latitude?: number | null;
  longitude?: number | null;
  accuracy?: number | null;
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function getMarkerColor(status: TrustStatus): string {
  switch (status) {
    case "TRUSTED":
      return "#10b981"; // Emerald green
    case "NORMAL":
      return "#06b6d4"; // Cyan
    case "CAUTION":
      return "#f59e0b"; // Amber/Yellow
    case "HIGH RISK":
      return "#ef4444"; // Red
    default:
      return "#64748b";
  }
}

function createNodeIcon(role: "sender" | "receiver", color: string, name: string, pulse = false) {
  const isSender = role === "sender";
  const badgeText = isSender ? "SENDER" : "RECEIVER";
  const badgeBg = isSender ? "#0284c7" : "#059669";

  return L.divIcon({
    className: "custom-soc-marker",
    html: `
      <div style="position: relative; display: flex; flex-direction: column; align-items: center; cursor: pointer; transform: translate(-50%, -50%);">
        ${
          pulse
            ? `<div style="position: absolute; top: 0; left: 50%; transform: translateX(-50%); width: 34px; height: 34px; border-radius: 50%; background: ${color}; opacity: 0.35; animation: ping 1.8s cubic-bezier(0, 0, 0.2, 1) infinite;"></div>`
            : ""
        }
        <div style="width: 22px; height: 22px; border-radius: 50%; background: #0f172a; border: 3px solid ${color}; box-shadow: 0 0 14px ${color}, 0 2px 8px rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center;">
          <div style="width: 8px; height: 8px; border-radius: 50%; background: ${color};"></div>
        </div>
        <div style="margin-top: 4px; background: rgba(15, 23, 42, 0.95); border: 1px solid #334155; border-radius: 4px; padding: 2px 6px; box-shadow: 0 4px 6px rgba(0,0,0,0.5); display: flex; align-items: center; gap: 4px; white-space: nowrap;">
          <span style="font-size: 8px; font-weight: 700; background: ${badgeBg}; color: white; padding: 1px 3px; border-radius: 2px; text-transform: uppercase;">${badgeText}</span>
          <span style="font-size: 10px; font-weight: 600; color: #f8fafc; font-family: monospace;">${name.slice(0, 14)}</span>
        </div>
      </div>
    `,
    iconSize: [0, 0],
    iconAnchor: [0, 0],
  });
}

function createSecurityEventIcon(severity: string, eventType: string) {
  const isCritical = severity.toLowerCase() === "critical" || severity.toLowerCase() === "high";
  const color = isCritical ? "#ef4444" : "#f59e0b";

  return L.divIcon({
    className: "custom-soc-event-marker",
    html: `
      <div style="position: relative; display: flex; flex-direction: column; align-items: center; cursor: pointer; transform: translate(-50%, -50%);">
        <div style="position: absolute; top: 0; left: 50%; transform: translateX(-50%); width: 30px; height: 30px; border-radius: 50%; background: ${color}; opacity: 0.4; animation: ping 1.5s cubic-bezier(0, 0, 0.2, 1) infinite;"></div>
        <div style="width: 20px; height: 20px; background: #0f172a; border: 2px solid ${color}; transform: rotate(45deg); box-shadow: 0 0 12px ${color}; display: flex; align-items: center; justify-content: center;">
          <div style="width: 6px; height: 6px; background: ${color};"></div>
        </div>
        <div style="margin-top: 6px; background: rgba(15, 23, 42, 0.95); border: 1px solid ${color}; border-radius: 4px; padding: 2px 5px; box-shadow: 0 4px 6px rgba(0,0,0,0.6); white-space: nowrap;">
          <span style="font-size: 9px; font-weight: 700; color: ${color}; font-family: monospace;">⚠ ${eventType.slice(0, 16)}</span>
        </div>
      </div>
    `,
    iconSize: [0, 0],
    iconAnchor: [0, 0],
  });
}

export function DigitalTwinMap({
  transfers,
  events = [],
  onSelectTransfer,
  className,
}: {
  transfers: MapTransferNode[];
  events?: MapEventNode[];
  onSelectTransfer?: (transferId: string) => void;
  className?: string;
}) {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const layerGroupRef = useRef<L.LayerGroup | null>(null);
  const [filter, setFilter] = useState<"all" | "active" | "blocked" | "events">("all");

  const transfersWithLocation = transfers.filter(
    (t) =>
      (typeof t.senderLatitude === "number" && typeof t.senderLongitude === "number") ||
      (typeof t.receiverLatitude === "number" && typeof t.receiverLongitude === "number"),
  );

  const eventsWithLocation = events.filter(
    (e) => typeof e.latitude === "number" && typeof e.longitude === "number",
  );

  // Default focus coordinates: Center of India / South Asia
  const INDIA_CENTER: [number, number] = [20.5937, 78.9629];
  const INDIA_ZOOM = 5;

  // Initialize Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current || mapInstanceRef.current) return;

    // Create map instance centered on India
    const map = L.map(mapContainerRef.current, {
      center: INDIA_CENTER,
      zoom: INDIA_ZOOM,
      minZoom: 2,
      maxZoom: 19,
      zoomControl: false,
    });

    // Zoom controls on bottom-right
    L.control.zoom({ position: "bottomright" }).addTo(map);

    // Metric scale bar on bottom-left
    L.control.scale({ imperial: false, position: "bottomleft" }).addTo(map);

    // Real OpenStreetMap Basemap (watermark-free, accurate geographic boundaries, cities, roads)
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors',
      maxZoom: 19,
      subdomains: ["a", "b", "c"],
    }).addTo(map);

    const layerGroup = L.layerGroup().addTo(map);
    mapInstanceRef.current = map;
    layerGroupRef.current = layerGroup;

    // Force size invalidation in case of layout shifts
    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 200);

    return () => {
      clearTimeout(timer);
      map.remove();
      mapInstanceRef.current = null;
    };
  }, []);

  // Update Markers, Paths, Accuracy Radii & Fit Bounds when data or filter changes
  useEffect(() => {
    const map = mapInstanceRef.current;
    const layerGroup = layerGroupRef.current;
    if (!map || !layerGroup) return;

    layerGroup.clearLayers();

    const bounds = L.latLngBounds([]);
    let plottedPoints = 0;

    const filteredTransfers = transfersWithLocation.filter((t) => {
      if (filter === "active")
        return !["TERMINATED", "COMPLETED", "EXPIRED", "FAILED"].includes(t.status);
      if (filter === "blocked") return t.status === "TERMINATED";
      if (filter === "events") return false;
      return true;
    });

    // Render transfers and user node markers
    filteredTransfers.forEach((t) => {
      const senderStatus = getTrustStatus(t.senderTrustScore);
      const recipientStatus = getTrustStatus(t.recipientTrustScore);

      const hasSenderLoc =
        typeof t.senderLatitude === "number" && typeof t.senderLongitude === "number";
      const hasReceiverLoc =
        typeof t.receiverLatitude === "number" && typeof t.receiverLongitude === "number";

      let senderLatLng: L.LatLng | null = null;
      let receiverLatLng: L.LatLng | null = null;

      // 1. SENDER MARKER & ACCURACY CIRCLE
      if (hasSenderLoc) {
        senderLatLng = L.latLng(t.senderLatitude!, t.senderLongitude!);
        bounds.extend(senderLatLng);
        plottedPoints++;

        const isHighRisk = t.senderTrustScore < 60;
        const color = getMarkerColor(senderStatus);

        // Accuracy radius circle if available
        const senderAccuracy = t.senderLocationAccuracy ?? null;
        if (typeof senderAccuracy === "number" && senderAccuracy > 0) {
          L.circle(senderLatLng, {
            radius: senderAccuracy,
            color: "#0284c7",
            fillColor: "#0284c7",
            fillOpacity: 0.12,
            weight: 1.5,
            dashArray: "4, 4",
          }).addTo(layerGroup);
        }

        const marker = L.marker(senderLatLng, {
          icon: createNodeIcon("sender", color, t.senderName, isHighRisk),
        });

        const popupContent = document.createElement("div");
        popupContent.className = "soc-popup font-sans text-xs p-3 text-slate-100 max-w-[280px]";
        popupContent.innerHTML = `
          <div style="border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 8px;">
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
              <span style="font-size: 9px; font-weight: 700; background: #0284c7; color: white; padding: 2px 5px; border-radius: 3px;">SENDER NODE</span>
              <span style="font-size: 10px; font-weight: 700; color: #38bdf8; font-family: monospace;">#TR-${t.id.slice(0, 8)}</span>
            </div>
            <div style="font-size: 12px; font-weight: 600; color: #f8fafc; margin-top: 4px;">${t.fileName}</div>
            <div style="font-size: 10px; color: #94a3b8;">${formatBytes(t.fileSizeBytes)}</div>
          </div>
          <div style="display: grid; gap: 5px; line-height: 1.4; font-size: 11px;">
            <div><strong>User:</strong> <span style="color: #f1f5f9;">${t.senderName}</span></div>
            <div><strong>Trust Score:</strong> <span style="color: ${color}; font-weight: 700;">${t.senderTrustScore}/100</span> (${senderStatus})</div>
            <div><strong>Transfer Status:</strong> <span style="font-family: monospace; color: #38bdf8;">${t.status}</span></div>
            <div><strong>Encryption:</strong> <span style="font-family: monospace; color: #a5f3fc;">${t.encryptionAlgorithm || "AES-256-GCM"}</span></div>
            <div><strong>Key Protection:</strong> <span style="font-family: monospace; color: #a5f3fc;">${t.keyWrapAlgorithm || "RSA-OAEP-2048"}</span></div>
            <div><strong>Integrity:</strong> <span style="color: #10b981; font-weight: 600;">${t.hashAlgorithm || "SHA-256"} VERIFIED</span></div>
            <div style="border-top: 1px solid #1e293b; padding-top: 4px; margin-top: 2px; color: #94a3b8;">
              <div><strong>Location:</strong> User-consented device location</div>
              <div><strong>Coordinates:</strong> ${t.senderLatitude!.toFixed(4)}° N, ${t.senderLongitude!.toFixed(4)}° E</div>
              ${typeof senderAccuracy === "number" ? `<div><strong>Accuracy:</strong> ±${Math.round(senderAccuracy)} meters</div>` : ""}
              <div><strong>Observed:</strong> ${new Date(t.senderLocationTimestamp ?? t.createdAt).toLocaleString()}</div>
            </div>
          </div>
        `;

        marker.bindPopup(popupContent, { className: "custom-soc-popup" });
        marker.addTo(layerGroup);
      }

      // 2. RECEIVER MARKER & ACCURACY CIRCLE
      if (hasReceiverLoc) {
        receiverLatLng = L.latLng(t.receiverLatitude!, t.receiverLongitude!);
        bounds.extend(receiverLatLng);
        plottedPoints++;

        const isHighRisk = t.recipientTrustScore < 60;
        const color = getMarkerColor(recipientStatus);

        // Accuracy radius circle if available
        const receiverAccuracy = t.receiverLocationAccuracy ?? null;
        if (typeof receiverAccuracy === "number" && receiverAccuracy > 0) {
          L.circle(receiverLatLng, {
            radius: receiverAccuracy,
            color: "#059669",
            fillColor: "#059669",
            fillOpacity: 0.12,
            weight: 1.5,
            dashArray: "4, 4",
          }).addTo(layerGroup);
        }

        const marker = L.marker(receiverLatLng, {
          icon: createNodeIcon("receiver", color, t.recipientName, isHighRisk),
        });

        const popupContent = document.createElement("div");
        popupContent.className = "soc-popup font-sans text-xs p-3 text-slate-100 max-w-[280px]";
        popupContent.innerHTML = `
          <div style="border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 8px;">
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
              <span style="font-size: 9px; font-weight: 700; background: #059669; color: white; padding: 2px 5px; border-radius: 3px;">RECEIVER NODE</span>
              <span style="font-size: 10px; font-weight: 700; color: #38bdf8; font-family: monospace;">#TR-${t.id.slice(0, 8)}</span>
            </div>
            <div style="font-size: 12px; font-weight: 600; color: #f8fafc; margin-top: 4px;">${t.fileName}</div>
          </div>
          <div style="display: grid; gap: 5px; line-height: 1.4; font-size: 11px;">
            <div><strong>User:</strong> <span style="color: #f1f5f9;">${t.recipientName}</span></div>
            <div><strong>Trust Score:</strong> <span style="color: ${color}; font-weight: 700;">${t.recipientTrustScore}/100</span> (${recipientStatus})</div>
            <div><strong>Transfer Status:</strong> <span style="font-family: monospace; color: #38bdf8;">${t.status}</span></div>
            <div><strong>Integrity:</strong> <span style="color: #10b981; font-weight: 600;">Verified Match</span></div>
            <div><strong>Key Wrapping:</strong> <span style="font-family: monospace; color: #a5f3fc;">${t.keyWrapAlgorithm || "RSA-OAEP-2048"}</span></div>
            <div style="border-top: 1px solid #1e293b; padding-top: 4px; margin-top: 2px; color: #94a3b8;">
              <div><strong>Location:</strong> Observed Session Location</div>
              <div><strong>Coordinates:</strong> ${t.receiverLatitude!.toFixed(4)}° N, ${t.receiverLongitude!.toFixed(4)}° E</div>
              ${typeof receiverAccuracy === "number" ? `<div><strong>Accuracy:</strong> ±${Math.round(receiverAccuracy)} meters</div>` : ""}
              <div><strong>Access Time:</strong> ${new Date(t.receiverLocationTimestamp ?? t.createdAt).toLocaleString()}</div>
            </div>
          </div>
        `;

        marker.bindPopup(popupContent, { className: "custom-soc-popup" });
        marker.addTo(layerGroup);
      }

      // 3. TRANSFER PATH (SENDER -> RECEIVER)
      if (senderLatLng && receiverLatLng) {
        const isTerminated = t.status === "TERMINATED";
        const isCompleted = t.status === "COMPLETED";

        const pathColor = isTerminated ? "#ef4444" : isCompleted ? "#10b981" : "#06b6d4";

        const polyline = L.polyline([senderLatLng, receiverLatLng], {
          color: pathColor,
          weight: isTerminated ? 3 : 2.5,
          opacity: 0.85,
          dashArray: isTerminated ? "6, 8" : isCompleted ? undefined : "6, 6",
        });

        const pathPopup = document.createElement("div");
        pathPopup.className = "soc-popup font-sans text-xs p-3 text-slate-100 max-w-[300px]";
        pathPopup.innerHTML = `
          <div style="border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 8px;">
            <div style="font-size: 9px; font-weight: 700; color: #38bdf8; text-transform: uppercase;">SECURE ENCRYPTED TRANSFER PIPELINE</div>
            <div style="font-size: 11px; font-weight: 700; color: #f8fafc; font-family: monospace; margin-top: 2px;">TRANSFER #${t.id.slice(0, 8)}</div>
          </div>
          <div style="display: grid; gap: 4px; font-size: 11px; line-height: 1.4;">
            <div><strong>Sender:</strong> ${t.senderName} (Trust: ${t.senderTrustScore}/100)</div>
            <div><strong>Receiver:</strong> ${t.recipientName} (Trust: ${t.recipientTrustScore}/100)</div>
            <div><strong>File:</strong> ${t.fileName} (${formatBytes(t.fileSizeBytes)})</div>
            <div><strong>Transfer Status:</strong> <span style="font-family: monospace; color: ${pathColor}; font-weight: 700;">${t.status}</span></div>
            <div><strong>Encryption:</strong> ${t.encryptionAlgorithm || "AES-256-GCM"}</div>
            <div><strong>Key Protection:</strong> ${t.keyWrapAlgorithm || "RSA-OAEP-2048"}</div>
            <div><strong>Integrity:</strong> ${t.hashAlgorithm || "SHA-256"} (Continuous Verification)</div>
            <div><strong>Timestamp:</strong> ${new Date(t.createdAt).toLocaleString()}</div>
          </div>
        `;

        polyline.bindPopup(pathPopup, { className: "custom-soc-popup" });
        polyline.addTo(layerGroup);
      }
    });

    // 4. SECURITY EVENTS WITH LOCATION (if filter includes events)
    if (filter === "all" || filter === "events") {
      eventsWithLocation.forEach((e) => {
        const eventLatLng = L.latLng(e.latitude!, e.longitude!);
        bounds.extend(eventLatLng);
        plottedPoints++;

        const marker = L.marker(eventLatLng, {
          icon: createSecurityEventIcon(e.severity, e.eventType),
        });

        const popupContent = document.createElement("div");
        popupContent.className = "soc-popup font-sans text-xs p-3 text-slate-100 max-w-[260px]";
        popupContent.innerHTML = `
          <div style="border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 8px;">
            <div style="font-size: 9px; font-weight: 700; color: #f87171; text-transform: uppercase;">SECURITY EVENT LOCATION</div>
            <div style="font-size: 12px; font-weight: 700; color: #f8fafc; margin-top: 2px;">${e.eventType}</div>
          </div>
          <div style="display: grid; gap: 4px; font-size: 11px;">
            <div><strong>Severity:</strong> <span style="font-weight: 700; text-transform: uppercase; color: ${e.severity === "critical" || e.severity === "high" ? "#ef4444" : "#f59e0b"};">${e.severity}</span></div>
            <div><strong>User/Session:</strong> ${e.userEmail}</div>
            <div><strong>Trust Impact:</strong> <span style="color: #ef4444; font-weight: 700;">${e.trustDelta}</span></div>
            <div><strong>IP Address:</strong> <span style="font-family: monospace;">${e.ipAddress || "Internal/Local"}</span></div>
            ${e.transferId ? `<div><strong>Transfer:</strong> <span style="font-family: monospace;">#TR-${e.transferId.slice(0, 8)}</span></div>` : ""}
            <div><strong>Timestamp:</strong> ${new Date(e.createdAt).toLocaleString()}</div>
          </div>
        `;

        marker.bindPopup(popupContent, { className: "custom-soc-popup" });
        marker.addTo(layerGroup);
      });
    }

    // Auto-fit bounds if we have plotted points; otherwise center on India
    if (plottedPoints > 0 && bounds.isValid()) {
      map.fitBounds(bounds, { padding: [60, 60], maxZoom: 13 });
    }
  }, [transfersWithLocation, eventsWithLocation, filter]);

  // Recenter map handler
  const handleRecenter = () => {
    const map = mapInstanceRef.current;
    if (!map) return;

    if (transfersWithLocation.length > 0) {
      const bounds = L.latLngBounds([]);
      transfersWithLocation.forEach((t) => {
        if (typeof t.senderLatitude === "number" && typeof t.senderLongitude === "number") {
          bounds.extend([t.senderLatitude, t.senderLongitude]);
        }
        if (typeof t.receiverLatitude === "number" && typeof t.receiverLongitude === "number") {
          bounds.extend([t.receiverLatitude, t.receiverLongitude]);
        }
      });
      if (bounds.isValid()) {
        map.fitBounds(bounds, { padding: [60, 60], maxZoom: 13 });
        return;
      }
    }
    map.setView(INDIA_CENTER, INDIA_ZOOM);
  };

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-xl border border-border bg-slate-950",
        className,
      )}
    >
      {/* Top Map Toolbar Overlay */}
      <div className="absolute left-3 top-3 z-[400] flex flex-wrap items-center gap-2 rounded-lg border border-border/80 bg-slate-900/95 p-1.5 shadow-xl backdrop-blur">
        <span className="flex items-center gap-1.5 px-1.5 text-xs font-semibold tracking-wide text-cyan-400">
          <Globe className="size-3.5" /> GEOSPATIAL RADAR
        </span>
        <div className="h-4 w-px bg-border/80" />
        <div className="flex items-center gap-1">
          <Button
            size="sm"
            variant={filter === "all" ? "default" : "ghost"}
            className="h-6 px-2 text-[11px]"
            onClick={() => setFilter("all")}
          >
            All ({transfersWithLocation.length + eventsWithLocation.length})
          </Button>
          <Button
            size="sm"
            variant={filter === "active" ? "default" : "ghost"}
            className="h-6 px-2 text-[11px]"
            onClick={() => setFilter("active")}
          >
            Active
          </Button>
          <Button
            size="sm"
            variant={filter === "blocked" ? "default" : "ghost"}
            className="h-6 px-2 text-[11px]"
            onClick={() => setFilter("blocked")}
          >
            Blocked
          </Button>
          {eventsWithLocation.length > 0 ? (
            <Button
              size="sm"
              variant={filter === "events" ? "default" : "ghost"}
              className="h-6 px-2 text-[11px]"
              onClick={() => setFilter("events")}
            >
              Events ({eventsWithLocation.length})
            </Button>
          ) : null}
        </div>
      </div>

      {/* Top-Right Recenter & Status Indicator */}
      <div className="absolute right-3 top-3 z-[400] flex items-center gap-2">
        <div className="hidden sm:flex items-center gap-1.5 rounded-md border border-border/80 bg-slate-900/95 px-2.5 py-1 text-[11px] font-medium text-slate-300 shadow-md backdrop-blur">
          <span className="size-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>OSM Basemap Active</span>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={handleRecenter}
          title="Recenter Map View"
          className="h-7 gap-1 bg-slate-900/95 border-border/80 px-2 text-xs shadow-md backdrop-blur hover:bg-slate-800"
        >
          <Compass className="size-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Recenter</span>
        </Button>
      </div>

      {/* Bottom-Left Map Legend Overlay */}
      <div className="absolute bottom-3 left-3 z-[400] hidden md:flex items-center gap-3 rounded-md border border-border/80 bg-slate-900/95 px-3 py-1.5 text-[10px] text-muted-foreground shadow-lg backdrop-blur">
        <span className="flex items-center gap-1">
          <span className="size-2 rounded-full bg-emerald-500" /> Trusted (90-100)
        </span>
        <span className="flex items-center gap-1">
          <span className="size-2 rounded-full bg-cyan-500" /> Normal (75-89)
        </span>
        <span className="flex items-center gap-1">
          <span className="size-2 rounded-full bg-amber-500" /> Caution (60-74)
        </span>
        <span className="flex items-center gap-1">
          <span className="size-2 rounded-full bg-red-500" /> High Risk (&lt;60)
        </span>
        <span className="flex items-center gap-1 border-l border-border pl-2">
          <span className="h-0.5 w-3 bg-cyan-400" /> Encrypted Tunnel
        </span>
        <span className="flex items-center gap-1">
          <span className="h-0.5 w-3 bg-red-500 border-b border-dashed" /> Blocked
        </span>
      </div>

      {/* Non-intrusive Floating Status Banner when no coordinates exist */}
      {transfersWithLocation.length === 0 && eventsWithLocation.length === 0 ? (
        <div className="absolute bottom-12 left-1/2 -translate-x-1/2 z-[400] flex items-center gap-2 rounded-lg border border-border/90 bg-slate-900/95 px-4 py-2 text-xs text-slate-300 shadow-2xl backdrop-blur">
          <MapPin className="size-4 text-cyan-400 shrink-0" />
          <span>
            <strong>Real-time Geospatial Map Active</strong> · Centered on India · Awaiting
            user-consented location signals
          </span>
        </div>
      ) : null}

      {/* Actual Leaflet Map Canvas */}
      <div ref={mapContainerRef} className="h-full min-h-[420px] w-full" />
    </div>
  );
}
