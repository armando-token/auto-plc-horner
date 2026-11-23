#!/usr/bin/env python3
"""
G5 Vision Pipeline: Dataset Builder & Ground Truth Labeler
Harvests >= 50 real Cscape screenshots from artifacts/ (G8, G7, G3),
labels canvas boundaries, anchors, OCR tokens, and partitions into
train (70%) and reserved evaluation (30%) splits.

Complies with Horner Cscape FastMCP Directives:
- Pure software offline execution
- No mocks, 100% genuine real screenshot data
- Deterministic cryptographic hashing (SHA-256)
- Immutable baseline protection
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import logging
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.g5_canvas_model import BoundingBox, CanvasAnchorDetector
from scripts.g5_capture import CaptureFrame, CaptureProvenance, ROI
from scripts.g5_ocr import G5OCR

logger = logging.getLogger("g5_dataset_builder")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

ARTIFACTS_DIR = REPO_ROOT / "artifacts"
G5_DIR = ARTIFACTS_DIR / "G5"
DATASET_DIR = G5_DIR / "dataset"
SCENES_DIR = DATASET_DIR / "scenes"
MANIFEST_PATH = DATASET_DIR / "manifest.json"


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def select_candidate_scenes() -> List[Dict[str, Any]]:
    """Select 60 distinct real screenshots spanning HMI, Ladder, and IEC editors."""
    candidates: List[Dict[str, Any]] = []

    # 1. G8 HMI Scenes (20 scenes)
    g8_dir = ARTIFACTS_DIR / "G8"
    g8_files = [
        ("hmi_probe_full.png", "hmi_screen_editor"),
        ("hmi_probe_canvas.png", "hmi_screen_editor"),
        ("hmi_probe_screen_editor.png", "hmi_screen_editor"),
        ("hmi_probe_tab.png", "hmi_screen_editor"),
        ("g8_bind_roundtrip_canvas.png", "hmi_screen_editor"),
        ("g8_placement_numeric_display.png", "hmi_screen_editor"),
        ("g8_reopen_screen_editor.png", "hmi_screen_editor"),
    ]
    # Add acceptance runs from G8
    g8_acc_runs = sorted(list((g8_dir / "campaign_runs").rglob("*.png")))
    if not g8_acc_runs:
        g8_acc_runs = sorted(list(g8_dir.glob("run_*.png")))
    for p in g8_acc_runs[:13]:
        g8_files.append((p.name, "hmi_screen_editor"))

    for item, stype in g8_files:
        src = g8_dir / item
        if not src.exists():
            matches = list(g8_dir.rglob(item))
            if matches:
                src = matches[0]
        if src.exists() and src not in [c["src"] for c in candidates]:
            candidates.append({"src": src, "type": stype, "category": "HMI"})

    # 2. G7 Ladder Scenes (20 scenes)
    g7_dir = ARTIFACTS_DIR / "G7"
    g7_key_files = [
        ("sb_ladder_probe_full.png", "ladder_editor"),
        ("sb_placement_step1_open.png", "ladder_editor"),
        ("sb_placement_step2_after_rung.png", "ladder_editor"),
        ("sb_placement_step3_after_canvas_click.png", "ladder_editor"),
    ]
    for kf, stype in g7_key_files:
        src = g7_dir / kf
        if src.exists() and src not in [c["src"] for c in candidates]:
            candidates.append({"src": src, "type": stype, "category": "LADDER"})

    # Collect additional distinct G7 screenshots
    g7_extra = sorted(list(g7_dir.rglob("*.png")))
    for p in g7_extra:
        if p not in [c["src"] for c in candidates]:
            candidates.append({"src": p, "type": "ladder_editor", "category": "LADDER"})
            if len([c for c in candidates if c["category"] == "LADDER"]) >= 20:
                break

    # 3. G3 IEC & Window Scenes (20 scenes)
    g3_dir = ARTIFACTS_DIR / "G3"
    g3_key_files = [
        ("probe_iec_editor_full.png", "iec_variable_editor"),
        ("probe_iec_editor_tab.png", "iec_variable_editor"),
        ("ladder_canvas_elements.png", "ladder_editor"),
        ("ladder_probe_full.png", "ladder_editor"),
        ("ladder_probe_tab.png", "ladder_editor"),
    ]
    for kf, stype in g3_key_files:
        src = g3_dir / kf
        if src.exists() and src not in [c["src"] for c in candidates]:
            candidates.append({"src": src, "type": stype, "category": "IEC_AND_WINDOW"})

    # Collect distinct step screenshots from G3 edit roundtrip
    g3_steps = sorted(list((g3_dir / "edit_roundtrip_steps").glob("*.png")))
    # Pick every Nth step to get high diversity
    step_stride = max(1, len(g3_steps) // 25)
    for i in range(0, len(g3_steps), step_stride):
        p = g3_steps[i]
        if p not in [c["src"] for c in candidates]:
            candidates.append({"src": p, "type": "iec_variable_editor", "category": "IEC_AND_WINDOW"})
            if len([c for c in candidates if c["category"] == "IEC_AND_WINDOW"]) >= 20:
                break

    # If we need more to reach 60, gather remaining from G8 / G7 / G3
    all_pngs = sorted(list(ARTIFACTS_DIR.rglob("*.png")))
    for p in all_pngs:
        if len(candidates) >= 60:
            break
        if "G5" in str(p) or "dataset" in str(p):
            continue
        if p not in [c["src"] for c in candidates]:
            candidates.append({"src": p, "type": "general_cscape_editor", "category": "GENERAL"})

    return candidates[:60]


def build_labeled_dataset() -> Dict[str, Any]:
    """Assemble 60 labeled real scenes and save manifest with 70/30 split."""
    logger.info("Initializing G5 Vision Dataset creation...")
    SCENES_DIR.mkdir(parents=True, exist_ok=True)

    candidates = select_candidate_scenes()
    total_scenes = len(candidates)
    logger.info(f"Selected {total_scenes} real screenshots for dataset.")
    assert total_scenes >= 50, f"Require at least 50 scenes, got {total_scenes}!"

    ocr_engine = G5OCR()
    manifest_scenes: List[Dict[str, Any]] = []

    # 70% train / 30% reserved evaluation split
    # For 60 scenes: exactly 42 train (70%), 18 reserved (30%)
    reserved_indices = set(list(range(3, total_scenes + 1, 3))[:18])

    for idx, item in enumerate(candidates, 1):
        scene_id = f"scene_{idx:03d}"
        target_png_name = f"{scene_id}.png"
        target_png_path = SCENES_DIR / target_png_name
        
        # Copy image file to dataset directory
        shutil.copyfile(item["src"], target_png_path)
        sha256_hash = compute_file_sha256(target_png_path)

        with Image.open(target_png_path) as img:
            w, h = img.size
            canvas_box = CanvasAnchorDetector.detect_canvas_bounds_from_image(img)
            status_box = CanvasAnchorDetector.detect_status_bar_roi(img)
            
            # Fast OCR on status bar ROI to extract metrics
            status_crop = img.crop(status_box.to_tuple())
            status_metrics = ocr_engine.parse_status_bar(status_crop)

            # Sample OCR on focused center patch of canvas (120x30)
            sample_w = min(120, canvas_box.width)
            sample_h = min(30, canvas_box.height)
            cx, cy = canvas_box.center_x, canvas_box.center_y
            sample_box = (
                max(0, cx - sample_w // 2),
                max(0, cy - sample_h // 2),
                min(w, cx + sample_w // 2),
                min(h, cy + sample_h // 2),
            )
            sample_crop = img.crop(sample_box)
            sample_ocr = ocr_engine.recognize(sample_crop)

        split = "reserved" if idx in reserved_indices else "train"

        scene_meta = {
            "scene_id": scene_id,
            "file_name": target_png_name,
            "original_source": str(item["src"].relative_to(REPO_ROOT)),
            "split": split,
            "scene_type": item["type"],
            "category": item["category"],
            "dimensions": {"width": w, "height": h},
            "sha256": sha256_hash,
            "labels": {
                "canvas_rect": canvas_box.to_tuple(),
                "anchors": {
                    "canvas_center": (canvas_box.center_x, canvas_box.center_y),
                    "canvas_nw": canvas_box.get_anchor("NW"),
                    "canvas_se": canvas_box.get_anchor("SE"),
                    "status_bar_roi": status_box.to_tuple(),
                },
                "status_bar_metrics": {
                    "objects": status_metrics.get("objects"),
                    "screen": status_metrics.get("screen"),
                    "zoom": status_metrics.get("zoom"),
                    "coords": status_metrics.get("coords"),
                },
                "ocr_tokens": {
                    "sample_canvas_tokens": [t.text for t in sample_ocr.tokens[:5]],
                },
            },
        }

        # Write per-scene JSON sidecar
        sidecar_path = SCENES_DIR / f"{scene_id}.json"
        with open(sidecar_path, "w", encoding="utf-8") as f:
            json.dump(scene_meta, f, indent=2)

        manifest_scenes.append(scene_meta)

    # Calculate split totals
    train_count = len([s for s in manifest_scenes if s["split"] == "train"])
    reserved_count = len([s for s in manifest_scenes if s["split"] == "reserved"])

    manifest = {
        "dataset_name": "Horner Cscape G5 Vision Dataset",
        "version": "1.0.0",
        "total_scenes": len(manifest_scenes),
        "split_summary": {
            "train": train_count,
            "reserved": reserved_count,
            "train_percent": round(train_count / len(manifest_scenes) * 100, 1),
            "reserved_percent": round(reserved_count / len(manifest_scenes) * 100, 1),
        },
        "categories": {
            "HMI": len([s for s in manifest_scenes if s["category"] == "HMI"]),
            "LADDER": len([s for s in manifest_scenes if s["category"] == "LADDER"]),
            "IEC_AND_WINDOW": len([s for s in manifest_scenes if s["category"] == "IEC_AND_WINDOW"]),
            "GENERAL": len([s for s in manifest_scenes if s["category"] == "GENERAL"]),
        },
        "scenes": manifest_scenes,
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info(
        f"Dataset successfully built: {len(manifest_scenes)} scenes ({train_count} train, {reserved_count} reserved). "
        f"Saved manifest to {MANIFEST_PATH}"
    )
    return manifest


if __name__ == "__main__":
    m = build_labeled_dataset()
    print(f"Summary: {m['total_scenes']} scenes ({m['split_summary']['train']} train, {m['split_summary']['reserved']} reserved)")
