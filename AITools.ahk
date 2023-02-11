; AITools.ahk: Some AI related tools

;; F10:
;; * Parse key-value text from clipboard and enter it into A1111/Invoke-AI web forms
;; * Supported formats:
;;   * AIMetaTools --mode TOKEYVALUE format
;;   * civitai
;; * Known issues / limitations:
;;   * Prompt textarea must be focused before pressing F10
;;   * Subsequent form fields are reached via Tab key (may not work in some
;;     cases, with newer versions, or with extensions installed that)
;;   * Invoke-AI has problems with Tab (inconsistent form-indexes)
;;   * Invoke-AI seed field must be visiable and editable (random off)

; {{{ = A1111 & Invoke-AI ====================================================
#HotIf WinActive("Stable Diffusion", )

global is_invokeai := WinActive("InvokeAI - A Stable Diffusion Toolkit")
global is_automatic1111 := !is_invokeai

; F10: Paste values from clipboard (if any) into A1111/Invoke-AI form
; assuming the main prompt-textarea is in focus
F10::
{
  ; brief check if shit somehow looks like the right stuff
  if (! InStr(A_Clipboard, "steps: ") && ! InStr(A_Clipboard, "cfg_scale: "))
  {
    ToolTip("No valid meta key-value map found in clipobard, skipping ...")
    SetTimer(ToolTip, 3000)
    return  ; wrong clipboard content
  }

  local dictstr := ""
  local prompt := ""
  local negative_prompt := ""
  local steps := ""
  local cfg_scale := ""
  local sampler := ""
  local height := ""
  local width := ""
  local seed := ""

  local clip := StrReplace(A_Clipboard, '`r', '')
  local n_count
  StrReplace(clip, "`n", "`n",, &n_count)
  ; quick check if this looks like civitai style format, if so convert it into our key-value format
  if (n_count == 2 && RegExMatch(clip, "i)^[^\n]+\n+negative prompt:[^\n]+\n.*(, (steps|cfg_scale|sampler|size|height|width|seed): .*){3}.*"))
  {
    ; values := 'prompt: ' . RegExReplace(values, "\n.*"
    a := StrSplit(clip, "`n",, 3)
    ;prompt := a[0]
    ;negative_prompt := RegExReplace(a[1], "i)negative[_ ]prompt: ", "")
    dictstr := "prompt: " . a[1] . '`n' . a[2] . '`n' . StrReplace(RegExReplace(a[3], "i)size: +([0-9]+)x([0-9]+)", "width: $1, height: $2"), ", ", "`n")
  }
  else
  {
    dictstr := clip
  }
  ;MsgBox dictstr

  ; parse clipboard
  Loop Parse, dictstr, "`n", "`r"
  {
    local key := StrLower(StrReplace(RegExReplace(A_LoopField, "^([^:]+):.*", "$1"), " ", "_"))
    ; only get values that we need
    if (! RegExMatch(key, "i)^(prompt|negative[_ ]prompt|steps|cfg[_ ]scale|sampler|height|width|seed)")) {
      Continue
    }
    local val := Trim(RegExReplace(A_LoopField, "^[^:]+:\s+", ""))
    ; TODO quick hack to normalize (some) sd-webui sampler names for invoke-ai
    if (!is_automatic1111 && key == "sampler" && InStr(val, " ")) {
      val := "k_" . RegExReplace(StrLower(val), " ", "_")
    }
    %key% := Trim(val)
    ;MsgBox key . " = " . val
  }

  ; in case of a1111 combined prompt split by negative prompt prefix
  ; TODO check if a1111 meta
  if (negative_prompt == "" && InStr(prompt, "Negative prompt: "))
  {
    parts := StrSplit(prompt, "Negative prompt: ",, 2)
    if (parts.Length >= 2)
    {
      prompt := parts[1]
      negative_prompt := parts[2]
    }
  }

  SendInput "^a"  ; select all
  ClipPaste(prompt)
  SendInput "{Tab}"
  SendInput "^a"  ; select all
  if (negative_prompt != "")
  {
    ClipPaste(negative_prompt)
  }
  else
  {
    Send "{Backspace}"  ; clear potentially existing negative prompt (since clip has none)
  }

  if (is_automatic1111)
  {
    SendInput "{Tab 9}"  ; skip buttons and image count
    SendText sampler
    SendInput "{Tab}"
    SendText steps
    SendInput "{Tab 5}"
    SendText width
    SendInput "{Tab 2}"
    SendText height
    SendInput "{Tab 7}"
    SendText cfg_scale
    SendInput "{Tab 2}"
    SendText seed
  }
  else  ; invoke-ai
  {
    SendInput "{Tab 3}"  ; skip buttons and image count
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
    ; FIXME for some reason this goes wild
    ; TODO this only works in case seed is unfolded and editable
    ;SendInput "{Tab 3}"
    ;SendText seed
  }
}

; https://tdalon.blogspot.com/2021/04/ahk-paste-restore-clipboard-pitfall.html
ClipPaste(text, restore := True)
{
  If (restore)
  {
    bak := A_Clipboard  ; only store plain text
  }
  A_Clipboard := text
  ClipWait 1
  SendInput "^v"
  If (restore)
  {
    Sleep 150
    While DllCall("user32\GetOpenClipboardWindow", "Ptr")
      Sleep 150
    A_Clipboard := bak
  }
}

#HotIf
; }}} = A1111 & Invoke-AI ====================================================
