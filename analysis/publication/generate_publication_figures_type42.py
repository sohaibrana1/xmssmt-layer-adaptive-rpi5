#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import math
import re
import sys
from pathlib import Path
from collections import defaultdict

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


# =========================================================
# Publication PDF font configuration.
# =========================================================

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42

mpl.rcParams["font.size"] = 9
mpl.rcParams["axes.labelsize"] = 9
mpl.rcParams["legend.fontsize"] = 8
mpl.rcParams["xtick.labelsize"] = 8
mpl.rcParams["ytick.labelsize"] = 8


(
    sign_path,
    table1_path,
    t1auth_path,
    model_path,
    signrows_path,
    pareto_path,
    pareto_input_path,
    fig1_path,
    fig2_path,
    fig3_path,
    fig4_path,
    fig2data_path,
    fig3data_path,
) = map(Path, sys.argv[1:14])


# =========================================================
# Helper
# =========================================================

def read_csv(path):
    with path.open(
        newline="",
        encoding="utf-8"
    ) as f:
        return list(csv.DictReader(f))


# =========================================================
# FIGURE 1
# Mean signing latency versus lower-layer height.
# Authoritative source:
# PARETO_VALIDATED_20CELL_INPUT.csv
# =========================================================

sign_rows = read_csv(sign_path)

if len(sign_rows) != 20:
    raise RuntimeError(
        f"Figure 1 expected 20 rows; found {len(sign_rows)}"
    )

series_order = [
    (16, 16),
    (16, 4),
    (4, 16),
    (4, 4),
]

markers = {
    (16, 16): "o",
    (16, 4): "s",
    (4, 16): "^",
    (4, 4): "D",
}

fig, ax = plt.subplots(
    figsize=(7.1, 4.35)
)

for pair in series_order:

    subset = [
        r for r in sign_rows
        if (
            int(r["w0"]),
            int(r["w1"])
        ) == pair
    ]

    subset.sort(
        key=lambda r: int(r["h0"])
    )

    x = [
        int(r["h0"])
        for r in subset
    ]

    y = [
        float(r["mean_sign_ms"])
        for r in subset
    ]

    ax.plot(
        x,
        y,
        marker=markers[pair],
        linewidth=1.35,
        markersize=5.5,
        label=rf"$w_0={pair[0]},\,w_1={pair[1]}$",
    )

ax.set_xlabel(
    r"Lower-layer height $h_0$"
)

ax.set_ylabel(
    "Mean signing latency (ms)"
)

ax.set_xticks(
    [6, 8, 10, 12, 14]
)

ax.grid(
    True,
    alpha=0.22,
    linewidth=0.6
)

ax.legend(
    ncol=2,
    frameon=True
)

fig.tight_layout()

fig.savefig(
    fig1_path,
    format="pdf",
    bbox_inches="tight"
)

plt.close(fig)

print("FIGURE1_GENERATION=PASS")


# =========================================================
# FIGURE 2
# Neighbor-relative rollover latency delta.
#
# h0=6,8,10,12:
# exact values currently published in Table 1.
#
# h0=14:
# use higher-precision pooled randomized values from the
# authoritative Gate11D-R3 foundation.
# =========================================================

table_text = table1_path.read_text(
    encoding="utf-8",
    errors="replace"
)

row_pattern = re.compile(
    r'^\s*'
    r'(\d+)\s*&\s*'
    r'(\d+)\s*&\s*'
    r'(\d+)\s*&\s*'
    r'(\d+)\s*&'
    r'.*?'
    r'&\s*'
    r'([-+]?\d+(?:\.\d+)?)\s*&\s*'
    r'(\d+)\s*&\s*'
    r'(\d+)\s*\\\\',
    re.M
)

published = {}

for m in row_pattern.finditer(table_text):

    h0 = int(m.group(1))
    h1 = int(m.group(2))
    w0 = int(m.group(3))
    w1 = int(m.group(4))

    delta = float(m.group(5))

    cfg = (
        f"H{h0}-{h1}_W{w0}-{w1}"
    )

    published[cfg] = {
        "configuration": cfg,
        "h0": h0,
        "h1": h1,
        "w0": w0,
        "w1": w1,
        "delta_pct": delta,
        "source":
            "TABLE1_PUBLISHED_NEIGHBOR_DELTA"
    }

if len(published) != 20:
    raise RuntimeError(
        f"Figure 2 Table-1 parser expected 20 rows; "
        f"found {len(published)}"
    )

auth_rows = read_csv(
    t1auth_path
)

for r in auth_rows:

    if int(r["h0"]) != 14:
        continue

    cfg = r["configuration"]

    value = (
        r[
            "h14_rollover_pooled_mean_delta_pct"
        ]
    )

    if not value:
        raise RuntimeError(
            f"Missing pooled h14 rollover delta for {cfg}"
        )

    if cfg not in published:
        raise RuntimeError(
            f"h14 config absent from Table 1: {cfg}"
        )

    published[cfg][
        "delta_pct"
    ] = float(value)

    published[cfg][
        "source"
    ] = (
        "GATE11D_R3_RANDOMIZED_POOLED_MEAN"
    )


fig2_rows = list(
    published.values()
)

fig2_rows.sort(
    key=lambda r: (
        r["w0"],
        r["w1"],
        r["h0"],
    )
)

with fig2data_path.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    fields = [
        "configuration",
        "h0",
        "h1",
        "w0",
        "w1",
        "rollover_neighbor_delta_pct",
        "source",
    ]

    w = csv.DictWriter(
        f,
        fieldnames=fields
    )

    w.writeheader()

    for r in fig2_rows:
        w.writerow({
            "configuration":
                r["configuration"],
            "h0":
                r["h0"],
            "h1":
                r["h1"],
            "w0":
                r["w0"],
            "w1":
                r["w1"],
            "rollover_neighbor_delta_pct":
                f"{r['delta_pct']:.12f}",
            "source":
                r["source"],
        })


fig, ax = plt.subplots(
    figsize=(7.1, 4.35)
)

for pair in series_order:

    subset = [
        r for r in fig2_rows
        if (
            r["w0"],
            r["w1"]
        ) == pair
    ]

    subset.sort(
        key=lambda r: r["h0"]
    )

    x = [
        r["h0"]
        for r in subset
    ]

    y = [
        r["delta_pct"]
        for r in subset
    ]

    ax.plot(
        x,
        y,
        marker=markers[pair],
        linewidth=1.35,
        markersize=5.5,
        label=rf"$w_0={pair[0]},\,w_1={pair[1]}$",
    )

ax.axhline(
    0,
    linewidth=0.8,
    linestyle="--"
)

ax.set_xlabel(
    r"Lower-layer height $h_0$"
)

ax.set_ylabel(
    "Rollover latency change (%)"
)

ax.set_xticks(
    [6, 8, 10, 12, 14]
)

ax.grid(
    True,
    alpha=0.22,
    linewidth=0.6
)

ax.legend(
    ncol=2,
    frameon=True
)

fig.tight_layout()

fig.savefig(
    fig2_path,
    format="pdf",
    bbox_inches="tight"
)

plt.close(fig)

print("FIGURE2_GENERATION=PASS")


# =========================================================
# FIGURE 3
#
# Rebuild from exactly the original aggregate-model input
# rows and frozen reported coefficients.
#
# Model:
# cycles =
#   intercept
#   + beta_hash * logical_hash_calls
#   + beta_tree * tree_nodes
# =========================================================

model_rows = read_csv(
    model_path
)

if len(model_rows) != 1:
    raise RuntimeError(
        "Expected one aggregate model row"
    )

model = model_rows[0]

intercept = float(
    model["intercept_cycles"]
)

beta_hash = float(
    model["cycles_per_logical_hash"]
)

beta_tree = float(
    model["cycles_per_tree_node"]
)

reported_r2 = float(
    model["r2"]
)

signing = read_csv(
    signrows_path
)

if len(signing) != 87316:
    raise RuntimeError(
        f"Expected 87316 signing rows; found {len(signing)}"
    )

measured = []
predicted = []

with fig3data_path.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    fields = [
        "configuration",
        "iteration",
        "measured_cycles",
        "logical_hash_calls",
        "tree_nodes",
        "predicted_cycles",
    ]

    w = csv.DictWriter(
        f,
        fieldnames=fields
    )

    w.writeheader()

    for r in signing:

        obs = float(
            r["cpu_cycles"]
        )

        logical = float(
            r["logical_hash_calls"]
        )

        tree = float(
            r["tree_nodes"]
        )

        pred = (
            intercept
            + beta_hash * logical
            + beta_tree * tree
        )

        measured.append(obs)
        predicted.append(pred)

        w.writerow({
            "configuration":
                r["configuration"],
            "iteration":
                r["iteration"],
            "measured_cycles":
                f"{obs:.6f}",
            "logical_hash_calls":
                f"{logical:.6f}",
            "tree_nodes":
                f"{tree:.6f}",
            "predicted_cycles":
                f"{pred:.6f}",
        })


# Verify recomputed R2 against the frozen model.
mean_obs = (
    sum(measured)
    / len(measured)
)

ss_res = sum(
    (y - p) ** 2
    for y, p in zip(
        measured,
        predicted
    )
)

ss_tot = sum(
    (y - mean_obs) ** 2
    for y in measured
)

calc_r2 = (
    1.0
    - ss_res / ss_tot
)

print(
    "FIGURE3_RECOMPUTED_R2=",
    f"{calc_r2:.12f}"
)

print(
    "FIGURE3_REPORTED_R2=",
    f"{reported_r2:.12f}"
)

if abs(
    calc_r2 - reported_r2
) > 1e-9:
    raise RuntimeError(
        "Figure 3 R2 does not reproduce frozen aggregate model"
    )


# Use a deterministic decimated display for rendering speed
# while the fitted statistics remain based on all 87,316 rows.
step = max(
    1,
    len(measured) // 12000
)

mx = measured[::step]
py = predicted[::step]

fig, ax = plt.subplots(
    figsize=(6.65, 4.45)
)

ax.scatter(
    mx,
    py,
    s=5,
    alpha=0.25,
    edgecolors="none"
)

lo = min(
    min(mx),
    min(py)
)

hi = max(
    max(mx),
    max(py)
)

ax.plot(
    [lo, hi],
    [lo, hi],
    linestyle="--",
    linewidth=1.0,
    label="Identity"
)

ax.set_xlabel(
    "Measured CPU cycles"
)

ax.set_ylabel(
    "Predicted CPU cycles"
)

ax.grid(
    True,
    alpha=0.20,
    linewidth=0.6
)

ax.text(
    0.04,
    0.95,
    rf"$R^2={reported_r2:.4f}$",
    transform=ax.transAxes,
    va="top",
)

ax.legend(
    loc="lower right",
    frameon=True
)

fig.tight_layout()

fig.savefig(
    fig3_path,
    format="pdf",
    bbox_inches="tight"
)

plt.close(fig)

print("FIGURE3_GENERATION=PASS")


# =========================================================
# FIGURE 4
#
# Reproduce Gate 11K design with Type-42 fonts.
# =========================================================

pareto_rows = read_csv(
    pareto_path
)

strict_members = None

for r in pareto_rows:

    if (
        r["scenario"] == "A"
        and r["definition"] == "strict"
        and r["epsilon_pct"] == "0"
    ):

        strict_members = {
            x
            for x in r["members"].split(";")
            if x
        }

        break

expected = {
    "H6-14_W4-4",
    "H6-14_W4-16",
    "H6-14_W16-16",
}

if strict_members != expected:
    raise RuntimeError(
        "Unexpected strict Scenario-A membership"
    )

raw = read_csv(
    pareto_input_path
)

data = []

for r in raw:

    data.append({
        "configuration":
            r["configuration"],
        "h0":
            int(r["h0"]),
        "h1":
            int(r["h1"]),
        "w0":
            int(r["w0"]),
        "w1":
            int(r["w1"]),
        "mean_sign_ms":
            float(r["mean_sign_ms"]),
        "signature_bytes":
            int(r["signature_bytes"]),
        "state_bytes":
            int(r["secret_key_bytes"]),
        "strict":
            r["configuration"]
            in strict_members,
    })


groups = defaultdict(list)

for r in data:
    groups[
        r["signature_bytes"]
    ].append(r)

for sig, group in groups.items():

    group.sort(
        key=lambda r: (
            r["mean_sign_ms"],
            r["configuration"]
        )
    )

    n = len(group)

    if n == 1:
        offsets = [0.0]
    else:
        offsets = [
            -64.0
            + i * (
                128.0 / (n - 1)
            )
            for i in range(n)
        ]

    for r, off in zip(
        group,
        offsets
    ):
        r["x"] = (
            r["signature_bytes"]
            + off
        )


state_min = min(
    r["state_bytes"]
    for r in data
)

state_max = max(
    r["state_bytes"]
    for r in data
)

norm = mpl.colors.Normalize(
    vmin=state_min,
    vmax=state_max
)

cmap = mpl.colormaps["viridis"]

fig, ax = plt.subplots(
    figsize=(7.25, 4.8)
)

dom = [
    r for r in data
    if not r["strict"]
]

ax.scatter(
    [r["x"] for r in dom],
    [r["mean_sign_ms"] for r in dom],
    s=64,
    marker="o",
    facecolor="lightgray",
    edgecolor="gray",
    linewidth=0.7,
    zorder=2,
)

ax.scatter(
    [r["x"] for r in dom],
    [r["mean_sign_ms"] for r in dom],
    s=22,
    marker="o",
    c=[
        r["state_bytes"]
        for r in dom
    ],
    cmap=cmap,
    norm=norm,
    edgecolor="none",
    zorder=3,
)

strict = [
    r for r in data
    if r["strict"]
]

ax.scatter(
    [r["x"] for r in strict],
    [r["mean_sign_ms"] for r in strict],
    s=105,
    marker="D",
    c=[
        r["state_bytes"]
        for r in strict
    ],
    cmap=cmap,
    norm=norm,
    edgecolor="black",
    linewidth=1.25,
    zorder=5,
)

label_offsets = {
    "H6-14_W4-4":
        (-760, 0.58),
    "H6-14_W4-16":
        (32, 0.66),
    "H6-14_W16-16":
        (34, 0.52),
}

for r in strict:

    dx, dy = label_offsets[
        r["configuration"]
    ]

    ax.annotate(
        rf"$({r['h0']},{r['h1']},"
        rf"{r['w0']},{r['w1']})$",
        xy=(
            r["x"],
            r["mean_sign_ms"]
        ),
        xytext=(
            r["x"] + dx,
            r["mean_sign_ms"] + dy
        ),
        fontsize=8.5,
        arrowprops=dict(
            arrowstyle="-",
            linewidth=0.65
        ),
        zorder=6,
    )

ax.set_xticks(
    [4963, 7075, 9187]
)

ax.set_xlabel(
    "Signature size (bytes)"
)

ax.set_ylabel(
    "Mean signing latency (ms)"
)

ax.grid(
    True,
    alpha=0.22,
    linewidth=0.6
)

ax.set_xlim(
    4720,
    9560
)

ax.set_ylim(
    max(
        0,
        min(
            r["mean_sign_ms"]
            for r in data
        ) - 1.0
    ),
    max(
        r["mean_sign_ms"]
        for r in data
    ) + 1.8
)

sm = mpl.cm.ScalarMappable(
    norm=norm,
    cmap=cmap
)

sm.set_array([])

cbar = fig.colorbar(
    sm,
    ax=ax,
    pad=0.025
)

cbar.set_label(
    "Serialized state (bytes)"
)

handles = [
    Line2D(
        [0],
        [0],
        marker="o",
        linestyle="none",
        markerfacecolor="lightgray",
        markeredgecolor="gray",
        markersize=7,
        label="Dominated / non-front"
    ),
    Line2D(
        [0],
        [0],
        marker="D",
        linestyle="none",
        markerfacecolor="white",
        markeredgecolor="black",
        markeredgewidth=1.2,
        markersize=8,
        label="Strict Scenario-A front"
    ),
]

ax.legend(
    handles=handles,
    loc="upper left",
    frameon=True
)

fig.tight_layout()

fig.savefig(
    fig4_path,
    format="pdf",
    bbox_inches="tight"
)

plt.close(fig)

print("FIGURE4_GENERATION=PASS")

print("ALL_FOUR_FIGURES_GENERATED=PASS")
