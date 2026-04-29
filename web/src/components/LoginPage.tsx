import { useEffect } from "react";

export function LoginPage() {
  useEffect(() => {
    window.location.replace("/login");
  }, []);

  return (
    <div className="h-[100dvh] flex items-center justify-center bg-cc-bg text-cc-fg font-sans-ui antialiased">
      <div className="w-full max-w-sm px-6">
        <div className="text-center mb-8">
          <h1 className="text-xl font-semibold text-cc-fg mb-2">Neuron Spark Code</h1>
          <p className="text-sm text-cc-muted">Redirecting to login...</p>
        </div>
      </div>
    </div>
  );
}
