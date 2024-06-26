import { useEffect, useState } from 'react'

export default function WasmLoader({children}) {
    const [isLoaded, setIsLoaded] = useState(false);

    useEffect(() => {
        const go = new window.Go();
        WebAssembly.instantiateStreaming(fetch("https://dev.shib.me/xipher/wasm/xipher.wasm"), go.importObject).then((result) => {
          go.run(result.instance);
          setIsLoaded(true);
        });
        
    },[])

  return isLoaded ? children : null;
}
