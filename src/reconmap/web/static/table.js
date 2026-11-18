"use strict";

// Filtro y orden de tablas en el cliente. Solo lee textContent: nunca inserta HTML.

document.addEventListener("input", (event) => {
  const input = event.target.closest("[data-filter]");
  if (!input) return;
  const table = document.querySelector(input.dataset.filter);
  const query = input.value.trim().toLowerCase();
  for (const row of table.tBodies[0].rows) {
    row.hidden = !row.textContent.toLowerCase().includes(query);
  }
});

document.addEventListener("click", (event) => {
  const header = event.target.closest("th[data-sort]");
  if (!header) return;
  const table = header.closest("table");
  const column = header.cellIndex;
  const ascending = header.getAttribute("aria-sort") !== "ascending";
  for (const th of header.parentElement.cells) th.removeAttribute("aria-sort");
  header.setAttribute("aria-sort", ascending ? "ascending" : "descending");

  const body = table.tBodies[0];
  const rows = Array.from(body.rows);
  rows.sort((a, b) => {
    const left = a.cells[column].textContent.trim();
    const right = b.cells[column].textContent.trim();
    const order = left.localeCompare(right, "es", { numeric: true });
    return ascending ? order : -order;
  });
  body.append(...rows);
});
