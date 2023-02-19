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
; Alt*F10: Toggle template prompts (vs. actual prompts)
; Shift*F10: Toggle seed unchanged (vs. setting it)
; For this to work it a) assuming the main prompt-textarea is in focus and
;   b) that no additional fields (e.g. from extensions) are in the way
; TODO consider providing a configration for this instead of 100 hotkeys
F10::
!F10::
+F10::
!+F10::
{
  ; in case alt was pressed use templates (if existing)
  local template_mode := GetKeyState("Alt")
  local no_seed_mode := GetKeyState("Shift")

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
  local template := ""
  local negative_template := ""
  local steps := ""
  local cfg_scale := ""
  local sampler := ""
  local height := ""
  local width := ""
  local seed := ""
  local batch_size := ""
  local batch_count := ""

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
  else  ; assuming ai-meta-tools format
  {
    dictstr := clip
  }
  ;MsgBox dictstr

  ; parse clipboard
  Loop Parse, dictstr, "`n", "`r"
  {
    local key := StrLower(StrReplace(Trim(RegExReplace(A_LoopField, "^([^:]+):.*", "$1")), " ", "_"))
    ; only get values that we need
    if (! RegExMatch(key, "i)^(prompt|template|negative[_ ](prompt|template)|steps|cfg[_ ]scale|sampler|height|width|seed|batch[_ ]size|batch[_ ]count)")) {
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

  ; in case alt was pressed use templates (if existing)
  if (template_mode && template != "")
  {
    AIToolsSend(template, true, true, true)
  }
  else
  {
    AIToolsSend(prompt, true, true, true)
  }

  SendInput "{Tab}"
  ; in case alt was pressed use templates (if existing)
  if (template_mode && negative_template != "")
  {
    AIToolsSend(negative_template, true, true, true)
  }
  else
  {
    AIToolsSend(negative_prompt, true, true, true)
  }

  ; TODO add other modifiers like "restore_face"

  if (is_automatic1111)
  {
    SendInput "{Tab 9}"
    AIToolsSend sampler
    SendInput "{Tab}"
    AIToolsSend steps
    SendInput "{Tab 5}"
    AIToolsSend width
    SendInput "{Tab 2}"
    AIToolsSend height
    SendInput "{Tab 3}"
    AIToolsSend batch_count
    SendInput "{Tab 2}"
    AIToolsSend batch_size
    SendInput "{Tab 2}"
    AIToolsSend cfg_scale
    if (!no_seed_mode)
    {
      SendInput "{Tab 2}"
      AIToolsSend seed
    }
  }
  else  ; invoke-ai
  {
    SendInput "{Tab 2}"
    AIToolsSend batch_size
    SendInput "^a"  ; select all
    AIToolsSend steps
    SendInput "{Tab}"
    SendInput "^a"  ; select all
    AIToolsSend cfg_scale
    SendInput "{Tab}"
    AIToolsSend width
    SendInput "{Tab}"
    AIToolsSend height
    SendInput "{Tab}"
    AIToolsSend sampler
    ; FIXME for some reason this goes wild
    ; TODO this only works in case seed is unfolded and editable
    ;if (!no_seed_mode)
    ;{
    ;  SendInput "{Tab 3}"
    ;  SendText seed
    ;}
  }
}


AIToolsSend(val, select_all:=false, paste:=false, clear_if_empty:=false)
{
  if (select_all)
  {
    SendInput "^a"  ; select all
  }
  if (Trim(val) != "")
  {
    if (paste)
    {
      ClipPaste(val)
    }
    else
    {
      SendText val
    }
  }
  else
  {
    if (clear_if_empty)
    {
      Send "{Backspace}"
    }
  }
}


; https://tdalon.blogspot.com/2021/04/ahk-paste-restore-clipboard-pitfall.html
ClipPaste(text, restore:=true)
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
