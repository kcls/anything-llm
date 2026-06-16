import React, { useState } from "react";
import { CaretDown, Check, CircleNotch } from "@phosphor-icons/react";

import AgentAnimation from "@/media/animations/agent-animation.webm";
import AgentStatic from "@/media/animations/agent-static.png";

export default function StatusResponse({ messages = [], isThinking = false }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const steps = messages;
  const currentStep = steps[steps.length - 1];
  const hasMultiple = steps.length > 1;
  if (!currentStep) return null;

  function toggleExpand() {
    if (!hasMultiple) return;
    setIsExpanded((prev) => !prev);
  }

  return (
    <div className="flex justify-center w-full pr-4">
      <div className="w-full flex flex-col">
        <div
          style={{ transition: "all 0.1s ease-in-out", borderRadius: "16px" }}
          className="relative bg-zinc-800 light:bg-slate-100 p-4"
        >
          {/* Header: overall state + latest step (or summary when expanded) */}
          <div
            onClick={toggleExpand}
            className={`flex items-center gap-x-3 ${hasMultiple ? "cursor-pointer" : ""}`}
          >
            <div className="w-[18px] h-[18px] flex-shrink-0">
              {isThinking ? (
                <video
                  autoPlay
                  loop
                  muted
                  playsInline
                  className="w-[18px] h-[18px] scale-[165%] transition-opacity duration-200 light:invert light:opacity-50"
                  data-tooltip-id="agent-thinking"
                  data-tooltip-content="Agent is working..."
                  aria-label="Agent is working..."
                >
                  <source src={AgentAnimation} type="video/webm" />
                </video>
              ) : (
                <img
                  src={AgentStatic}
                  alt="Agent finished"
                  className="w-[18px] h-[18px] transition-opacity duration-200 light:invert light:opacity-50"
                  data-tooltip-id="agent-thinking"
                  data-tooltip-content="Agent has finished"
                  aria-label="Agent has finished"
                />
              )}
            </div>

            <div className="flex-1 min-w-0 text-zinc-200 light:text-slate-800 font-mono text-sm leading-[18px]">
              {isExpanded ? (
                <span className="opacity-60">
                  {isThinking ? "Working…" : `${steps.length} steps`}
                </span>
              ) : (
                <span className="block w-full truncate">
                  {currentStep.content}
                </span>
              )}
            </div>

            {hasMultiple && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  toggleExpand();
                }}
                className="flex-shrink-0 border-none text-zinc-200 light:text-slate-800 transition-colors"
                data-tooltip-id="expand-cot"
                data-tooltip-content={
                  isExpanded ? "Hide steps" : "Show all steps"
                }
                aria-label={isExpanded ? "Hide steps" : "Show all steps"}
              >
                <CaretDown
                  className={`w-4 h-4 transform transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`}
                />
              </button>
            )}
          </div>

          {/* Expanded: the full step timeline */}
          {isExpanded && (
            <div className="mt-3 ml-[8px] flex flex-col gap-y-2 border-l border-white/10 light:border-black/10 pl-4">
              {steps.map((step, index) => {
                const isActive = isThinking && index === steps.length - 1;
                return (
                  <div
                    key={`step-${step.uuid || index}`}
                    className="flex items-start gap-x-2"
                  >
                    <div className="w-[14px] h-[14px] mt-[2px] flex-shrink-0 text-zinc-300 light:text-slate-700">
                      {isActive ? (
                        <CircleNotch className="w-[14px] h-[14px] animate-spin" />
                      ) : (
                        <Check className="w-[14px] h-[14px] opacity-70" />
                      )}
                    </div>
                    <div className="text-zinc-200 light:text-slate-800 font-mono text-sm leading-[18px]">
                      {step.content}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
