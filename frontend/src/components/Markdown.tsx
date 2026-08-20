import ReactMarkdown from "react-markdown";

/** Renders LLM-generated markdown narratives (reports, briefings). */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="text-sm text-slate-300 leading-relaxed space-y-3 [&_h1]:text-base [&_h1]:font-semibold [&_h1]:text-white [&_h2]:text-sm [&_h2]:font-semibold [&_h2]:text-white [&_h3]:text-sm [&_h3]:font-semibold [&_h3]:text-white [&_strong]:text-white [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:space-y-1 [&_ol]:list-decimal [&_ol]:pl-5 [&_ol]:space-y-1 [&_code]:bg-kahu-elevated [&_code]:px-1 [&_code]:rounded [&_code]:text-xs [&_a]:text-kahu-accent [&_hr]:border-kahu-border">
      <ReactMarkdown>{children}</ReactMarkdown>
    </div>
  );
}
