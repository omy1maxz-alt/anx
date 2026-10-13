import React, { useState, useRef, useEffect } from 'react';
import {
  X,
  Send,
  Sparkles,
  Bot,
  User,
  Trash2,
  Copy,
  Check,
  Smartphone,
  ShieldAlert,
  Loader2,
  HelpCircle,
  Cpu,
} from 'lucide-react';
import { InvestigationSession } from '../types/forensics';

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  content: string;
  timestamp: string;
}

interface ChatBotModalProps {
  isOpen: boolean;
  onClose: () => void;
  session: InvestigationSession;
  activeDexName?: string;
  appliedPatchesCount?: number;
  onOpenMtGuide?: () => void;
  onOpenConverter?: () => void;
}

export const ChatBotModal: React.FC<ChatBotModalProps> = ({
  isOpen,
  onClose,
  session,
  activeDexName = 'classes10.dex',
  appliedPatchesCount = 0,
  onOpenMtGuide,
  onOpenConverter,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    return [
      {
        id: 'msg-welcome',
        role: 'model',
        content: `👋 **Hello! I'm your DroidForensics AI Copilot.**

I can help you inspect Android APKs, fix adware/Chrome auto-redirects, analyze \`${activeDexName}\`, provide exact Smali patches, or walk you through MT Manager on your phone.

Tap any quick prompt below or type your question!`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ];
  });

  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom of messages
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen, isLoading]);

  // Focus input on open
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSend = async (textToSend?: string) => {
    const text = (textToSend || input).trim();
    if (!text || isLoading) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}-user`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const newHistory = [...messages, userMsg];
    setMessages(newHistory);
    setInput('');
    setIsLoading(true);

    try {
      const sessionContext = {
        packageName: session.manifest?.packageName || 'Target APK',
        targetDexName: activeDexName,
        classesCount: session.parsedClasses.length,
        findingsCount: session.findings.length,
        findings: session.findings.map((f) => ({
          title: f.title,
          severity: f.severity,
          className: f.className,
          methodName: f.methodName,
        })),
        appliedPatchesCount,
        targetBehavior: session.targetBehavior,
      };

      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: newHistory.map((m) => ({
            role: m.role,
            content: m.content,
          })),
          sessionContext,
        }),
      });

      const data = await res.json();
      const replyText =
        data.reply ||
        'I received your request. Let me know if you would like me to analyze a specific class or explain MT Manager steps.';

      const botMsg: ChatMessage = {
        id: `msg-${Date.now()}-model`,
        role: 'model',
        content: replyText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, botMsg]);
    } catch {
      const errorMsg: ChatMessage = {
        id: `msg-${Date.now()}-error`,
        role: 'model',
        content: `⚠️ Failed to connect to server. Check your connection or try again. You can also view the in-app MT Manager Guide directly.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearChat = () => {
    setMessages([
      {
        id: 'msg-cleared',
        role: 'model',
        content: `Chat history cleared. How can I assist with your APK or Smali files?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
  };

  const copyToClipboard = (code: string, blockId: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCodeId(blockId);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  const quickPrompts = [
    'How to stop Chrome ads in classes10.dex?',
    'MT Manager: Step-by-step DEX replacement',
    'Explain .registers vs .locals in Smali',
    'Analyze current session findings',
  ];

  // Helper to render markdown and code blocks
  const renderMessageContent = (content: string, msgId: string) => {
    const parts = content.split(/(```[\s\S]*?```)/g);

    return parts.map((part, index) => {
      if (part.startsWith('```')) {
        const lines = part.slice(3, -3).split('\n');
        const lang = lines[0].trim();
        const code = (lang ? lines.slice(1) : lines).join('\n').trim();
        const blockId = `${msgId}-code-${index}`;
        const isCopied = copiedCodeId === blockId;

        return (
          <div key={index} className="my-2.5 rounded-xl overflow-hidden border border-slate-700 bg-slate-950/90 text-xs">
            <div className="flex items-center justify-between px-3 py-1.5 bg-slate-800/80 border-b border-slate-700/80 text-[11px] text-slate-300">
              <span className="font-mono text-cyan-400 font-semibold">{lang || 'smali'}</span>
              <button
                onClick={() => copyToClipboard(code, blockId)}
                className="flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-200 active:scale-95 transition-all"
                title="Copy code"
              >
                {isCopied ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-[10px] text-emerald-300 font-semibold">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3 text-slate-400" />
                    <span className="text-[10px]">Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 overflow-x-auto font-mono text-[11px] leading-relaxed text-emerald-300 selection:bg-emerald-900/60">
              <code>{code}</code>
            </pre>
          </div>
        );
      }

      // Format bold, bullet points, headers
      const lines = part.split('\n');
      return (
        <div key={index} className="space-y-1">
          {lines.map((line, lIdx) => {
            if (!line.trim()) return <div key={lIdx} className="h-1.5" />;

            if (line.startsWith('### ')) {
              return (
                <h4 key={lIdx} className="text-xs font-bold text-cyan-300 mt-2 mb-1">
                  {line.replace('### ', '')}
                </h4>
              );
            }
            if (line.startsWith('## ')) {
              return (
                <h3 key={lIdx} className="text-xs font-bold text-cyan-200 mt-2.5 mb-1">
                  {line.replace('## ', '')}
                </h3>
              );
            }
            if (line.startsWith('- ') || line.startsWith('• ')) {
              return (
                <div key={lIdx} className="flex items-start space-x-1.5 text-xs text-slate-200 pl-1 leading-relaxed">
                  <span className="text-cyan-400 font-bold">•</span>
                  <span>{formatInlineMarkdown(line.slice(2))}</span>
                </div>
              );
            }
            if (/^\d+\.\s/.test(line)) {
              return (
                <div key={lIdx} className="text-xs text-slate-200 pl-1 leading-relaxed">
                  {formatInlineMarkdown(line)}
                </div>
              );
            }

            return (
              <p key={lIdx} className="text-xs leading-relaxed text-slate-200">
                {formatInlineMarkdown(line)}
              </p>
            );
          })}
        </div>
      );
    });
  };

  const formatInlineMarkdown = (text: string) => {
    const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
    return parts.map((seg, i) => {
      if (seg.startsWith('`') && seg.endsWith('`')) {
        return (
          <code key={i} className="px-1 py-0.5 mx-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[11px] border border-slate-700">
            {seg.slice(1, -1)}
          </code>
        );
      }
      if (seg.startsWith('**') && seg.endsWith('**')) {
        return (
          <strong key={i} className="font-bold text-white">
            {seg.slice(2, -2)}
          </strong>
        );
      }
      return seg;
    });
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/98 backdrop-blur-xl flex flex-col font-sans select-none antialiased pt-[env(safe-area-inset-top)] pb-[env(safe-area-inset-bottom)] animate-in fade-in zoom-in-95 duration-200">
      {/* Top Header */}
      <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-slate-800 bg-slate-900/90 shadow-md">
        <div className="flex items-center space-x-2.5 min-w-0">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center shadow-md shadow-cyan-950/50 shrink-0">
            <Bot className="w-4 h-4 text-white" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center space-x-1.5">
              <h2 className="text-xs font-bold text-white tracking-tight truncate">DroidForensics AI Copilot</h2>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            </div>
            <div className="flex items-center space-x-1 text-[10px] text-slate-400">
              <span className="truncate">Gemini 3.8 Flash & Dalvik Expert</span>
              <span className="text-slate-600">•</span>
              <span className="truncate text-cyan-400 font-mono">{activeDexName}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-1 shrink-0">
          <button
            onClick={handleClearChat}
            className="w-9 h-9 rounded-lg hover:bg-slate-800 active:scale-95 text-slate-400 hover:text-slate-200 flex items-center justify-center transition-all"
            title="Clear chat history"
            aria-label="Clear chat"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          <button
            onClick={onClose}
            className="w-9 h-9 rounded-lg bg-slate-800/80 hover:bg-slate-700 active:scale-95 text-slate-300 hover:text-white flex items-center justify-center transition-all border border-slate-700"
            title="Close Chat"
            aria-label="Close Chat"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Session Context Bar */}
      <div className="bg-slate-900/60 border-b border-slate-800/80 px-3 py-1.5 flex items-center justify-between text-[11px] text-slate-400 overflow-x-auto whitespace-nowrap">
        <div className="flex items-center space-x-2">
          <span className="flex items-center space-x-1 text-cyan-400 font-medium">
            <Cpu className="w-3 h-3" />
            <span>Target: {activeDexName}</span>
          </span>
          <span className="text-slate-600">|</span>
          <span>{session.parsedClasses.length} Classes</span>
          <span className="text-slate-600">|</span>
          <span className={session.findings.length > 0 ? 'text-rose-400 font-semibold' : 'text-emerald-400'}>
            {session.findings.length} Finding(s)
          </span>
        </div>
        <div className="flex items-center space-x-2 pl-3">
          {onOpenMtGuide && (
            <button
              onClick={() => {
                onClose();
                onOpenMtGuide();
              }}
              className="text-emerald-400 hover:underline flex items-center space-x-1"
            >
              <Smartphone className="w-3 h-3" />
              <span>MT Guide</span>
            </button>
          )}
        </div>
      </div>

      {/* Messages Thread Container */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3.5">
        {messages.map((msg) => {
          const isUser = msg.role === 'user';
          return (
            <div
              key={msg.id}
              className={`flex items-start space-x-2 ${isUser ? 'flex-row-reverse space-x-reverse' : ''}`}
            >
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5 shadow-sm ${
                  isUser
                    ? 'bg-gradient-to-tr from-cyan-600 to-indigo-600 text-white'
                    : 'bg-slate-800 text-cyan-400 border border-slate-700'
                }`}
              >
                {isUser ? <User className="w-3.5 h-3.5" /> : <Bot className="w-3.5 h-3.5" />}
              </div>

              <div
                className={`rounded-2xl px-3.5 py-2.5 max-w-[86%] shadow-md ${
                  isUser
                    ? 'bg-gradient-to-r from-cyan-600 to-indigo-600 text-white rounded-tr-xs'
                    : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-tl-xs'
                }`}
              >
                {renderMessageContent(msg.content, msg.id)}
                <div
                  className={`text-[9px] mt-1 text-right ${
                    isUser ? 'text-cyan-100/70' : 'text-slate-500'
                  }`}
                >
                  {msg.timestamp}
                </div>
              </div>
            </div>
          );
        })}

        {isLoading && (
          <div className="flex items-start space-x-2">
            <div className="w-7 h-7 rounded-lg bg-slate-800 text-cyan-400 border border-slate-700 flex items-center justify-center shrink-0 mt-0.5">
              <Bot className="w-3.5 h-3.5 animate-pulse" />
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-2xl rounded-tl-xs px-3.5 py-2.5 flex items-center space-x-2 text-slate-400 text-xs shadow-md">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
              <span>Analyzing Smali bytecode & formulating guidance...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts Bar */}
      <div className="px-3 py-1.5 border-t border-slate-800/80 bg-slate-900/60 overflow-x-auto whitespace-nowrap scrollbar-none flex items-center space-x-1.5">
        <Sparkles className="w-3 h-3 text-cyan-400 shrink-0 ml-0.5" />
        {quickPrompts.map((prompt, pIdx) => (
          <button
            key={pIdx}
            onClick={() => handleSend(prompt)}
            disabled={isLoading}
            className="px-2.5 py-1 rounded-full bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-300 hover:text-cyan-300 border border-slate-700/80 text-[10px] font-medium transition-all shrink-0 disabled:opacity-50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Input Bar */}
      <div className="p-2.5 bg-slate-900/95 border-t border-slate-800 shadow-xl">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-end space-x-2 max-w-lg mx-auto"
        >
          <div className="flex-1 relative">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              placeholder="Ask about classes, Chrome adware, MT Manager, or Smali..."
              rows={1}
              className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl px-3 py-2 text-xs text-slate-100 placeholder-slate-500 outline-none resize-none min-h-[42px] max-h-24 leading-relaxed"
            />
          </div>

          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="w-11 h-11 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 active:scale-95 disabled:opacity-40 disabled:pointer-events-none text-white flex items-center justify-center shadow-lg shadow-cyan-950/50 transition-all shrink-0"
            aria-label="Send Message"
          >
            {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          </button>
        </form>
      </div>
    </div>
  );
};
