"use strict";

// Grafo de entidades con Cytoscape.js. Cytoscape se carga solo al abrir la pestaña.
// Los datos externos se pintan con textContent (o en el canvas), nunca como HTML.

const CYTOSCAPE = {
  src: "https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js",
  integrity: "sha384-IWROdLKRsN1UuJywMlWl7/blXQ8GEooN2n7dzTxfEPd7ybYIKCUJ2Ol/1Gpf3YV4",
};

const TYPES = {
  domain: { name: "Dominio", color: "#4fa3f7", shape: "star", size: 48 },
  subdomain: { name: "Subdominio", color: "#7cc4ff", shape: "round-rectangle", size: 24 },
  ip: { name: "IP", color: "#5cc98a", shape: "ellipse", size: 22 },
  asn: { name: "Sistema autónomo", color: "#b48cf2", shape: "hexagon", size: 30 },
  org: { name: "Organización", color: "#f28cc4", shape: "diamond", size: 32 },
  port: { name: "Puerto", color: "#f2b84b", shape: "triangle", size: 14 },
  certificate: { name: "Certificado", color: "#8b95a3", shape: "tag", size: 18 },
  url: { name: "URL archivada", color: "#6f7a88", shape: "rectangle", size: 14 },
  candidate: { name: "Candidato", color: "#f2665c", shape: "vee", size: 18 },
};

let cytoscapeLoading = null;

function loadCytoscape() {
  if (window.cytoscape) return Promise.resolve();
  cytoscapeLoading ??= new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = CYTOSCAPE.src;
    script.integrity = CYTOSCAPE.integrity;
    script.crossOrigin = "anonymous";
    script.onload = resolve;
    script.onerror = () => reject(new Error("No se pudo cargar la librería del grafo"));
    document.head.append(script);
  });
  return cytoscapeLoading;
}

function graphStyle() {
  const byType = Object.entries(TYPES).map(([type, t]) => ({
    selector: `node[type = "${type}"]`,
    style: { "background-color": t.color, shape: t.shape, width: t.size, height: t.size },
  }));
  return [
    {
      selector: "node",
      style: {
        label: "data(short)",
        color: "#e3e7ec",
        "font-size": 9,
        "text-valign": "bottom",
        "text-margin-y": 4,
        "text-outline-color": "#0f1216",
        "text-outline-width": 2,
        "min-zoomed-font-size": 4,
      },
    },
    ...byType,
    { selector: 'node[type = "certificate"], node[type = "port"], node[type = "url"]', style: { "min-zoomed-font-size": 9 } },
    { selector: "node[?group]", style: { "border-width": 2, "border-style": "dashed", "border-color": "#e3e7ec", width: 34, height: 34 } },
    {
      selector: "edge",
      style: {
        width: 1,
        "line-color": "#3a4350",
        "target-arrow-color": "#3a4350",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.6,
        "curve-style": "bezier",
      },
    },
    { selector: ".faded", style: { opacity: 0.12 } },
    { selector: "node:selected", style: { "border-width": 3, "border-color": "#ffffff" } },
  ];
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function showDetails(panel, node) {
  const type = TYPES[node.type] ?? { name: node.type };
  const list = element("dl");
  for (const [key, value] of Object.entries(node.details)) {
    list.append(element("dt", key), element("dd", value));
  }
  panel.replaceChildren(
    element("p", type.name, "graph-panel-type"),
    element("h3", node.label, "graph-panel-title"),
    element("p", node.sources.length ? `Fuentes: ${node.sources.join(", ")}` : "", "muted"),
    list,
  );
}

function buildLegend(legend, present) {
  legend.replaceChildren(
    ...Object.entries(TYPES)
      .filter(([type]) => present.has(type))
      .map(([, t]) => {
        const item = element("li");
        const swatch = element("span", undefined, "legend-swatch");
        swatch.style.background = t.color;
        item.append(swatch, element("span", t.name));
        return item;
      }),
  );
}

function render(root, data) {
  const status = root.querySelector(".graph-status");
  const panel = root.querySelector(".graph-panel");
  if (!data.nodes.length) {
    status.textContent = "Este escaneo no tiene entidades que dibujar.";
    return;
  }
  const nodes = new Map(data.nodes.map((n) => [n.id, n]));
  const cy = window.cytoscape({
    container: root.querySelector(".graph-canvas"),
    elements: [
      ...data.nodes.map((n) => ({ data: { id: n.id, type: n.type, short: n.short, group: n.group } })),
      ...data.edges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target } })),
    ],
    style: graphStyle(),
    layout: { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 70, padding: 30 },
    wheelSensitivity: 0.25,
    minZoom: 0.1,
    maxZoom: 4,
  });

  cy.on("tap", "node", (event) => {
    cy.elements().addClass("faded");
    event.target.closedNeighborhood().removeClass("faded");
    showDetails(panel, nodes.get(event.target.id()));
  });
  cy.on("tap", (event) => {
    if (event.target === cy) cy.elements().removeClass("faded");
  });
  root.querySelector("[data-action=fit]").addEventListener("click", () => {
    cy.elements().removeClass("faded");
    cy.fit(undefined, 30);
  });

  buildLegend(root.querySelector(".graph-legend"), new Set(data.nodes.map((n) => n.type)));
  const grouped = data.grouped.length ? ` · agrupados: ${data.grouped.join(", ")}` : "";
  status.textContent = `${data.nodes.length} nodos · ${data.edges.length} relaciones${grouped}`;
}

async function initGraphs() {
  for (const root of document.querySelectorAll("[data-graph-url]:not([data-ready])")) {
    root.dataset.ready = "1";
    const status = root.querySelector(".graph-status");
    try {
      await loadCytoscape();
      const response = await fetch(root.dataset.graphUrl);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      render(root, await response.json());
    } catch (error) {
      status.textContent = `No se pudo dibujar el grafo: ${error.message}`;
    }
  }
}

document.addEventListener("DOMContentLoaded", initGraphs);
document.addEventListener("htmx:afterSettle", initGraphs);
