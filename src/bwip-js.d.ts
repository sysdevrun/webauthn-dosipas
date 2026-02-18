declare module "bwip-js" {
  interface RenderOptions {
    bcid: string;
    text: string;
    scale?: number;
    includetext?: boolean;
    height?: number;
    width?: number;
    [key: string]: unknown;
  }

  function toCanvas(
    canvas: HTMLCanvasElement | string,
    opts: RenderOptions,
  ): HTMLCanvasElement;

  export default { toCanvas };
  export { toCanvas, RenderOptions };
}
