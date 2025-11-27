export class SuperDB {
    static async instantiate(url) {
        const resp = await fetch(url);
        if (!resp.ok) throw new Error(`Failed to fetch WASM: ${resp.statusText}`);
        
        let buffer = await resp.arrayBuffer();
        
        const view = new Uint8Array(buffer);
        if (view[0] === 0x1f && view[1] === 0x8b) {
            const ds = new DecompressionStream("gzip");
            const stream = new Blob([buffer]).stream().pipeThrough(ds);
            buffer = await new Response(stream).arrayBuffer();
        }
        
        return this.createInstance(buffer)
            .then((instance) => new SuperDB(instance));
    }

    static async createInstance(buffer) {
        const go = new Go();
        const { instance } = await WebAssembly.instantiate(buffer, go.importObject);
        go.run(instance);
        return __go_wasm__;
    }

    constructor(instance) {
        this.instance = instance;
    }

    run(args) {
        return this.instance.zq({
            input: args.input,
            inputFormat: args.inputFormat || "auto",
            program: args.query,
            outputFormat: args.outputFormat || "zjson",
        });
    }
}