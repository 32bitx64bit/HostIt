package protocol

type EmailListenerStatus struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Addr      string `json:"addr,omitempty"`
	Listening bool   `json:"listening"`
	Details   string `json:"details,omitempty"`
}

type EmailProbeRequest struct {
	Username        string `json:"username,omitempty"`
	Address         string `json:"address,omitempty"`
	InboundProbeID  string `json:"inboundProbeId,omitempty"`
	OutboundProbeID string `json:"outboundProbeId,omitempty"`
	OutboundTarget  string `json:"outboundTarget,omitempty"`
	OutboundRcpt    string `json:"outboundRcpt,omitempty"`
	TimeoutSeconds  int    `json:"timeoutSeconds,omitempty"`
}

type EmailProbeResult struct {
	ListenerChecks  []EmailListenerStatus `json:"listenerChecks,omitempty"`
	InboundReady    bool                  `json:"inboundReady"`
	InboundSummary  string                `json:"inboundSummary,omitempty"`
	OutboundReady   bool                  `json:"outboundReady"`
	OutboundSummary string                `json:"outboundSummary,omitempty"`
	Error           string                `json:"error,omitempty"`
}
