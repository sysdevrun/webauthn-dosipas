/**
 * Aztec code rendering using bwip-js.
 *
 * Renders an Aztec barcode to a canvas element from a string payload.
 */

import bwipjs from "bwip-js";

/**
 * Render an Aztec code onto a canvas element.
 * @param canvas  Target canvas element
 * @param data    String data to encode
 * @param scale   Module scale (default 3)
 */
export async function renderAztecCode(
  canvas: HTMLCanvasElement,
  data: string,
  scale = 3,
): Promise<void> {
  bwipjs.toCanvas(canvas, {
    bcid: "azteccode",
    text: data,
    scale,
    includetext: false,
  });
}
