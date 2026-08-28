import { useEffect, useState } from "react";

/**
 * Reads the viewer's motion preference and keeps it live.
 *
 * Anything that animates must consult this. The Pipeline Rail is the only
 * animated element in the interface, and it must render complete and still
 * when the viewer has asked for reduced motion.
 */
export function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(
    () =>
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true,
  );

  useEffect(() => {
    const query = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!query) return undefined;
    const onChange = (event) => setReduced(event.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  return reduced;
}
