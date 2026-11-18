"use strict";

// Grafo de entidades con Cytoscape.js. Cytoscape se carga solo al abrir la pestaña.
// Los datos externos se pintan con textContent (o en el canvas), nunca como HTML.

const CYTOSCAPE = {
  src: "https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js",
  integrity: "sha384-IWROdLKRsN1UuJywMlWl7/blXQ8GEooN2n7dzTxfEPd7ybYIKCUJ2Ol/1Gpf3YV4",
};

const TYPES = {
  domain: { name: "Dominio", color: "#2563eb", shape: "star", size: 48 },
  subdomain: { name: "Subdominio", color: "#60a5fa", shape: "round-rectangle", size: 24 },
  ip: { name: "IP", color: "#22a35a", shape: "ellipse", size: 22 },
  asn: { name: "Sistema autónomo", color: "#8b5cf6", shape: "hexagon", size: 30 },
  org: { name: "Organización", color: "#db2777", shape: "diamond", size: 32 },
  port: { name: "Puerto", color: "#f59e0b", shape: "triangle", size: 14 },
  certificate: { name: "Certificado", color: "#94a3b8", shape: "tag", size: 18 },
  url: { name: "URL archivada", color: "#64748b", shape: "rectangle", size: 14 },
  candidate: { name: "Candidato", color: "#dc2626", shape: "vee", size: 18 },
};

const STATUS_LABELS = { ok: "Correcto", warn: "Mejorable", fail: "Problema", info: "Info" };

// Disposición de fuerzas: más repulsión y aristas más largas = nodos más separados.
const LAYOUT = {
  name: "cose",
  animate: false,
  randomize: true,
  nodeDimensionsIncludeLabels: true,
  nodeRepulsion: 60000,
  nodeOverlap: 30,
  idealEdgeLength: 90,
  edgeElasticity: 100,
  gravity: 0.5,
  componentSpacing: 120,
  numIter: 2500,
  padding: 40,
};

const PLAYBACK_SECONDS = 12;
const TICK_MS = 40;
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
        color: "#1f2933",
        "font-size": 9,
        "text-valign": "bottom",
        "text-margin-y": 4,
        "text-outline-color": "#ffffff",
        "text-outline-width": 2,
        "min-zoomed-font-size": 4,
      },
    },
    ...byType,
    { selector: 'node[type = "certificate"], node[type = "port"], node[type = "url"]', style: { "min-zoomed-font-size": 9 } },
    { selector: "node[?group]", style: { "border-width": 2, "border-style": "dashed", "border-color": "#637083", width: 34, height: 34 } },
    { selector: 'node[worst = "warn"]', style: { "border-width": 3, "border-color": "#d97706" } },
    { selector: 'node[worst = "fail"]', style: { "border-width": 4, "border-color": "#c62828" } },
    {
      selector: "edge",
      style: {
        width: 1,
        "line-color": "#c7cfda",
        "target-arrow-color": "#c7cfda",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.6,
        "curve-style": "bezier",
      },
    },
    { selector: ".faded", style: { opacity: 0.12 } },
    { selector: ".hidden", style: { display: "none" } },
    { selector: ".fresh", style: { "underlay-color": "#2563eb", "underlay-opacity": 0.25, "underlay-padding": 6 } },
    { selector: "node:selected", style: { "underlay-color": "#2563eb", "underlay-opacity": 0.18, "underlay-padding": 8 } },
  ];
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function badge(status) {
  return element("span", STATUS_LABELS[status] ?? status, `badge badge-${status}`);
}

// Panel lateral

function renderInsights(panel, data, onSelect) {
  const problems = element("ul", undefined, "insight-problems");
  for (const check of data.problems) {
    const item = element("li");
    const body = element("div");
    body.append(element("strong", check.control), element("span", ` ${check.summary}`));
    if (check.advice) body.append(element("p", check.advice, "muted"));
    item.append(badge(check.status), body);
    problems.append(item);
  }

  const info = element("dl");
  for (const [key, value] of data.info) info.append(element("dt", key), element("dd", value));

  const related = element("ul", undefined, "insight-related");
  for (const link of data.related) {
    const item = element("li");
    const button = element("button", link.label, "link-button");
    button.type = "button";
    button.addEventListener("click", () => onSelect(link.id));
    item.append(element("span", link.relation, "muted"), button);
    related.append(item);
  }

  panel.replaceChildren(
    element("p", data.type_label, "graph-panel-type"),
    element("h3", data.title, "graph-panel-title"),
    element("h4", "Posibles problemas"),
    data.problems.length ? problems : element("p", "Nada que señalar para este tipo de nodo.", "muted"),
    element("h4", "Información"),
    info,
    ...(data.related.length ? [element("h4", "Relacionado"), related] : []),
  );
}

function renderGroup(panel, node) {
  const info = element("dl");
  for (const [key, value] of Object.entries(node.details)) info.append(element("dt", key), element("dd", value));
  panel.replaceChildren(
    element("p", "Grupo", "graph-panel-type"),
    element("h3", node.label, "graph-panel-title"),
    element("p", "Se agrupan para que el grafo siga siendo legible; el detalle está en las pestañas y en el JSON.", "muted"),
    info,
  );
}

// Línea de tiempo

function timeline(root, cy, nodes) {
  const slider = root.querySelector("[data-timeline]");
  const label = root.querySelector(".timeline-label");
  const play = root.querySelector("[data-action=play]");
  const ordered = [...nodes].sort((a, b) => a.order - b.order);
  const reveal = new Map(ordered.map((n) => [n.id, n.order]));
  const edgeStep = (edge) => Math.max(reveal.get(edge.data("source")), reveal.get(edge.data("target")));
  const start = new Date(ordered[0].seen).getTime();
  let timer = null;

  slider.max = String(ordered.length);
  slider.value = slider.max;

  function show(step) {
    cy.batch(() => {
      cy.nodes().forEach((n) => {
        const order = reveal.get(n.id());
        n.toggleClass("hidden", order >= step);
        n.toggleClass("fresh", order === step - 1 && step < ordered.length);
      });
      cy.edges().forEach((e) => e.toggleClass("hidden", edgeStep(e) >= step));
    });
    slider.value = String(step);
    const last = ordered[Math.min(step, ordered.length) - 1];
    if (!last || step >= ordered.length) {
      label.textContent = `Grafo completo · ${ordered.length} nodos`;
      return;
    }
    const seconds = ((new Date(last.seen).getTime() - start) / 1000).toFixed(1);
    const type = TYPES[last.type]?.name ?? last.type;
    label.textContent = `Paso ${step}/${ordered.length} · +${seconds} s · ${type}: ${last.short}`;
  }

  function stop() {
    clearInterval(timer);
    timer = null;
    play.textContent = "▶ Reproducir";
  }

  play.addEventListener("click", () => {
    if (timer) return stop();
    let step = Number(slider.value) >= ordered.length ? 0 : Number(slider.value);
    const perTick = Math.max(1, Math.ceil(ordered.length / ((PLAYBACK_SECONDS * 1000) / TICK_MS)));
    play.textContent = "⏸ Pausa";
    timer = setInterval(() => {
      step = Math.min(ordered.length, step + perTick);
      show(step);
      if (step >= ordered.length) stop();
    }, TICK_MS);
  });
  slider.addEventListener("input", () => {
    stop();
    show(Number(slider.value));
  });
  const linkedStep = Number(new URLSearchParams(location.hash.slice(1)).get("paso"));
  show(linkedStep > 0 && linkedStep < ordered.length ? linkedStep : ordered.length);
}

// Montaje

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
      ...data.nodes.map((n) => ({
        data: { id: n.id, type: n.type, short: n.short, group: n.group, worst: n.worst ?? "" },
      })),
      ...data.edges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target } })),
    ],
    style: graphStyle(),
    layout: LAYOUT,
    wheelSensitivity: 0.25,
    minZoom: 0.05,
    maxZoom: 4,
  });

  async function select(id) {
    const target = cy.getElementById(id);
    if (target.length) {
      cy.elements().removeClass("hidden").addClass("faded");
      target.closedNeighborhood().removeClass("faded");
      cy.$(":selected").unselect();
      target.select();
      cy.animate({ center: { eles: target }, zoom: Math.max(cy.zoom(), 1.2) }, { duration: 300 });
    }

    const node = nodes.get(id);
    if (node?.group) return renderGroup(panel, node);
    panel.replaceChildren(element("p", "Cargando…", "muted"));
    try {
      const response = await fetch(`${root.dataset.nodeUrl}?id=${encodeURIComponent(id)}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      renderInsights(panel, await response.json(), select);
    } catch (error) {
      panel.replaceChildren(element("p", `No se pudo cargar el detalle: ${error.message}`, "muted"));
    }
  }

  cy.on("tap", "node", (event) => select(event.target.id()));
  cy.on("tap", (event) => {
    if (event.target === cy) cy.elements().removeClass("faded");
  });
  root.querySelector("[data-action=fit]").addEventListener("click", () => {
    cy.elements().removeClass("faded");
    cy.fit(undefined, 30);
  });
  root.querySelector("[data-action=relayout]").addEventListener("click", () => {
    cy.layout(LAYOUT).run();
  });

  const legend = root.querySelector(".graph-legend");
  const present = new Set(data.nodes.map((n) => n.type));
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
    element("li", "Borde rojo/ámbar: el nodo tiene problemas", "legend-note"),
  );

  timeline(root, cy, data.nodes);
  const grouped = data.grouped.length ? ` · agrupados: ${data.grouped.join(", ")}` : "";
  status.textContent = `${data.nodes.length} nodos · ${data.edges.length} relaciones${grouped}`;

  // Enlace directo a un nodo: /scans/<id>?tab=graph#nodo=ip:192.0.2.10
  const linked = new URLSearchParams(location.hash.slice(1)).get("nodo");
  if (linked) select(linked);
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
