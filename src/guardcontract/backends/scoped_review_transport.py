"""Minimal wire profile over the existing authenticated recorded transport."""
import json
import urllib.error
from pathlib import Path

from guardcontract.backends.recorded import RecordedTransport,bounded_http,save
from guardcontract.backends.provider_endpoint import REQUIRED_THINKING

ALLOWED_EXTERNAL_MODEL = "GLM-5.3-Flash"
CALL_STATE = Path(__file__).resolve().parents[3] / "config/external-model-call-state.json"


class ScopedReviewTransport(RecordedTransport):
    def __init__(self,directory,**kwargs):
        if kwargs.get("model") != ALLOWED_EXTERNAL_MODEL:
            raise ValueError("external_model_policy_requires_GLM-5.3-Flash")
        directory=Path(directory)
        injected='transport' in kwargs
        request_impl=kwargs.pop('transport',bounded_http)
        if not injected:
            state=json.loads(CALL_STATE.read_text())
            if state.get('enabled') is not True:
                raise ValueError('external_model_calls_paused')
        def request(url,headers,body,timeout):
            try:return request_impl(url,headers,body,timeout)
            except urllib.error.HTTPError as exc:
                raw=exc.read(16384)
                try:
                    error=json.loads(raw).get('error',{})
                    message=error.get('message','') if isinstance(error,dict) else str(error)
                except (ValueError,UnicodeError):message='non_json_provider_error'
                token=headers.get('Authorization','').removeprefix('Bearer ')
                if token:message=message.replace(token,'<credential-redacted>')
                save(directory/'HTTP_ERROR.json',{'status':exc.code,'message':message[:1000]})
                raise
        super().__init__(directory,transport=request,**kwargs)

    def __call__(self,url,headers,body,timeout):
        request=json.loads(body)
        # The official platform always reasons and rejects disabled thinking
        # (code 1210). The frozen wire profile pins the lowest reasoning
        # budget explicitly so hidden reasoning cannot consume the completion
        # budget unnoticed (n1892 lesson); the caller must send it verbatim.
        if request.get('thinking') != REQUIRED_THINKING:
            raise ValueError('GLM-5.3-Flash_requires_explicit_low_budget_thinking')
        return super().__call__(url,headers,json.dumps(request,separators=(',',':')).encode(),timeout)
