//! Keep a custom Docker profile as canonical JSON all the way to the guest.
//! A path received through the API is never read on the Mac.
use super::engine::Error;

pub fn profile(options: &[String]) -> Result<Option<String>, Error> {
    let mut selected = None;
    for option in options {
        if let Some(value) = option
            .strip_prefix("seccomp=")
            .or_else(|| option.strip_prefix("seccomp:"))
        {
            if selected.replace(value).is_some() {
                return Err(Error::BadRequest("more than one seccomp option".into()));
            }
        }
    }
    let Some(value) = selected else {
        return Ok(None);
    };
    if matches!(value, "unconfined" | "default") {
        return Ok(None);
    }
    let json: serde_json::Value = serde_json::from_str(value).map_err(|_| {
        Error::BadRequest("custom seccomp must be a JSON object, not a host path".into())
    })?;
    if !json.is_object()
        || !matches!(
            json["defaultAction"].as_str(),
            Some(
                "SCMP_ACT_ALLOW"
                    | "SCMP_ACT_ERRNO"
                    | "SCMP_ACT_KILL"
                    | "SCMP_ACT_KILL_THREAD"
                    | "SCMP_ACT_KILL_PROCESS"
                    | "SCMP_ACT_TRAP"
                    | "SCMP_ACT_TRACE"
                    | "SCMP_ACT_LOG"
            )
        )
    {
        return Err(Error::BadRequest(
            "invalid or unsupported seccomp defaultAction".into(),
        ));
    }
    Ok(Some(json.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_profile_is_data_and_is_kept_for_start_and_exec() {
        let text = "{\n\"defaultAction\":\"SCMP_ACT_ERRNO\",\"syscalls\":[]\n}";
        let mut spec: super::super::engine::Spec = serde_json::from_value(serde_json::json!({
            "image":"test", "image_id":"", "entrypoint":[], "cmd":[], "env":[],
            "cwd":"/", "user":"", "auto_remove":false, "network_mode":"none", "labels":{}
        }))
        .unwrap();
        spec.security_opt = vec![format!("seccomp={text}")];
        let lines = spec.guest_opts(false).unwrap();
        assert_eq!(
            lines.iter().filter(|s| s.starts_with("seccomp\t")).count(),
            1
        );
        let line = lines.iter().find(|s| s.starts_with("seccomp\t")).unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line[8..]).unwrap()["defaultAction"],
            "SCMP_ACT_ERRNO"
        );
    }
    #[test]
    fn invalid_and_ambiguous_policies_never_become_the_default_filter() {
        for options in [
            vec!["seccomp=/etc/passwd"],
            vec!["seccomp={}"],
            vec!["seccomp=[]"],
            vec!["seccomp=default", "seccomp=unconfined"],
        ] {
            assert!(profile(&options.iter().map(|v| v.to_string()).collect::<Vec<_>>()).is_err());
        }
        assert!(profile(&["seccomp=default".into()]).unwrap().is_none());
        assert!(profile(&["seccomp=unconfined".into()]).unwrap().is_none());
    }
}
