; InvokeAI.ahk: Some tweaks for Invoke-AI (Web)

; {{{ = Run == ===============================================================
#HotIf WinActive("InvokeAI - A Stable Diffusion Toolkit", )

; F10: Paste json values from clipboard (if any) into Invoke-AI form
; expects prompt-textarea to be focused (uses tab to navigate through form)
F10::
{
  if (! InStr(A_Clipboard, "steps: ") && ! InStr(A_Clipboard, "cfg_scale: "))
  {
    ToolTip("No valid InvokeAI key-value map found in clipobard, skipping ...")
    SetTimer(ToolTip, 3000)
    return  ; wrong clipboard content
  }
  local prompt := ""
  local prompt_negative := ""  ; TODO parse if not existing
  local steps := ""
  local cfg_scale := ""
  local sampler := ""
  local height := ""
  local width := ""
  local seed := ""
  ; parse clipboard
  Loop Parse, A_Clipboard, "`n", "`r"
  {
    local key := RegExReplace(A_LoopField, "[ :].*", "")
    ; only get values that we need
    if (! RegExMatch(key, "(prompt|steps|cfg_scale|sampler|height|width|seed)")) {
      Continue
    }
    local val := RegExReplace(A_LoopField, ".*:\s*", "")
    ; TODO quick hack to normalize (some) sd-webui sampler names
    if (key == "sampler" && InStr(val, " ")) {
      val := "k_" . RegExReplace(StrLower(val), " ", "_")
    }
    %key% := val
  }
  SendInput "^a"  ; select all
  Send "{Tex}" . prompt
  SendInput "{Tab}"
  SendInput "^a"  ; select all
  SendText prompt_negative
  SendInput "{Tab}"
  SendInput "{Tab}"  ; skip invoke/cancel button
  SendInput "{Tab}"  ; skip images (count)
  SendInput "^a"  ; select all
  SendText steps
  SendInput "{Tab}"
  SendInput "^a"  ; select all
  SendText cfg_scale
  SendInput "{Tab}"
  SendText width
  SendInput "{Tab}"
  SendText height
  SendInput "{Tab}"
  SendText sampler
}

#HotIf
