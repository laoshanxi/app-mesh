# bash completion for appmesh CLI (appc) -*- shell-script -*-

_appc() {
    local cur prev words cword
    _init_completion || return
    
    # Top-level subcommands and aliases from CommandDispatcher
    local commands="logon logoff logout loginfo \
    list ls view \
    add reg rm remove unreg \
    enable disable restart \
    run exec shell \
    join cloud nodes \
    get put \
    label log config resource \
    passwd mfa lock user \
    appmgpwd appmginit"
    
    case "${prev}" in
        # Options that expect an app name
        -a|--app)
            # Get application names (ignore header)
            local apps
            apps="$(appc ls -l 2>/dev/null | awk 'NR>1 {print $2}')"
            COMPREPLY=( $(compgen -W "${apps}" -- "${cur}") )
            return
        ;;
        # Help/version options - no further completion
        -h|-v|--help|--version)
            return
        ;;
    esac
    
    # If completing the first argument after 'appc'
    if [[ ${cword} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
        return
    fi
    
    # Context-aware completions for some subcommands
    case "${words[1]}" in
        get|put)
            _filedir
            return
        ;;
        *)
            # Default fallback (files only if relevant)
        ;;
    esac
}

complete -F _appc appc
