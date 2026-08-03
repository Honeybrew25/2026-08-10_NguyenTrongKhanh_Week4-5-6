from __future__ import annotations

from importlib.resources import files
import json
from typing import Any, Protocol, Sequence

from security_pipeline.analysis.models import (
    NarrativeBatch,
    NarrativeDraft,
    NarrativeRequest,
)


class ProviderError(RuntimeError):
    """Raised when a narrative provider cannot return a valid grounded draft."""


class NarrativeProvider(Protocol):
    name: str

    def generate(self, requests: Sequence[NarrativeRequest]) -> NarrativeBatch:
        """Return exactly one narrative for every requested group."""


_EXPLANATIONS = {
    ("bandit", "b101"): (
        "Bandit cảnh báo việc dùng assert. Assert có thể bị loại bỏ khi Python "
        "chạy ở chế độ tối ưu, vì vậy cần xác minh nó chỉ phục vụ kiểm thử và "
        "không phải là kiểm soát bảo mật của production."
    ),
    ("bandit", "b105"): (
        "Bandit nhận diện một chuỗi có từ khóa liên quan đến mật khẩu. Bằng "
        "chứng scanner có thể chỉ là hằng URL chứa chữ token, nên đây là tín "
        "hiệu cần review chứ chưa chứng minh secret bị hard-code."
    ),
    ("bandit", "b310"): (
        "Bandit cảnh báo lời gọi mở URL có thể chấp nhận scheme ngoài dự kiến. "
        "Các giá trị hiện thấy có thể là hằng nội bộ, nhưng vẫn cần kiểm tra "
        "xem dữ liệu không tin cậy có thể đi tới lời gọi này hay không."
    ),
    ("bandit", "b404"): (
        "Bandit đánh dấu việc import module subprocess vì module này có thể "
        "được dùng để chạy lệnh hệ điều hành. Chỉ riêng thao tác import chưa "
        "chứng minh có command injection."
    ),
    ("bandit", "b603"): (
        "Bandit cảnh báo lời gọi subprocess cần được kiểm tra nguồn gốc argv. "
        "Việc dùng shell=False giảm rủi ro chèn lệnh nhưng không thay thế việc "
        "xác minh dữ liệu đầu vào."
    ),
    ("zap", "10021"): (
        "ZAP ghi nhận response thiếu X-Content-Type-Options: nosniff. Đây là "
        "thiếu lớp hardening của trình duyệt và cần xác minh trên response thực tế."
    ),
    ("zap", "90004-1"): (
        "ZAP ghi nhận Cross-Origin-Resource-Policy bị thiếu hoặc chưa phù hợp. "
        "Cần chọn chính sách theo cách tài nguyên được chia sẻ giữa các origin."
    ),
    ("zap", "10049-1"): (
        "ZAP phân loại các response này là không được lưu cache. Đây là thông "
        "tin về hành vi cache, không tự nó chứng minh một lỗ hổng có thể khai thác."
    ),
    ("zap", "10049-3"): (
        "ZAP ghi nhận response có thể được lưu cache. Cần đối chiếu nội dung "
        "response với chính sách cache mong muốn trước khi kết luận có rủi ro."
    ),
}

_VERIFICATION_STEPS = {
    ("bandit", "b101"): [
        "Kiểm tra từng assert có nằm ngoài test hoặc script xác minh hay không.",
        "Xác nhận không assert nào đang bảo vệ authorization, input validation hoặc invariant production.",
    ],
    ("bandit", "b105"): [
        "Đọc giá trị chuỗi trong ngữ cảnh và xác định đó là secret hay chỉ là URL/hằng cấu hình.",
        "Kiểm tra secret thật được lấy từ biến môi trường hoặc secret manager và không nằm trong source.",
    ],
    ("bandit", "b310"): [
        "Trace nguồn dữ liệu truyền vào lời gọi mở URL và xác định người dùng có thể điều khiển nó hay không.",
        "Thử các scheme không được phép trong môi trường test và xác nhận chương trình từ chối chúng.",
    ],
    ("bandit", "b404"): [
        "Tìm các lời gọi subprocess liên quan và kiểm tra xem lệnh hoặc tham số có nhận input bên ngoài hay không."
    ],
    ("bandit", "b603"): [
        "Xác nhận argv là danh sách cố định hoặc được allowlist và shell luôn được tắt.",
        "Thử giá trị biên trong môi trường test để bảo đảm input không thể thay đổi chương trình được gọi.",
    ],
    ("zap", "10021"): [
        "Gửi lại request trong môi trường test và kiểm tra response có header nosniff hay chưa."
    ],
    ("zap", "90004-1"): [
        "Kiểm tra header CORP trên cả response thành công và response lỗi trong môi trường test.",
        "Xác nhận chính sách đã chọn phù hợp với các origin thực sự cần đọc tài nguyên.",
    ],
    ("zap", "10049-1"): [
        "Đối chiếu cache header của từng response với chính sách vận hành mong muốn."
    ],
    ("zap", "10049-3"): [
        "Xác nhận response không chứa dữ liệu nhạy cảm trước khi cho phép browser hoặc proxy cache."
    ],
}

_REMEDIATION_STEPS = {
    ("bandit", "b101"): [
        "Thay assert dùng cho kiểm soát runtime bằng validation và exception tường minh.",
        "Giữ assert chỉ trong test hoặc kiểm tra nội bộ không ảnh hưởng an toàn production.",
    ],
    ("bandit", "b105"): [
        "Nếu là secret thật, chuyển giá trị sang biến môi trường hoặc secret manager và rotate secret đã lộ.",
        "Nếu là false positive, ghi lại lý do review hoặc suppression hẹp cho đúng dòng/rule.",
    ],
    ("bandit", "b310"): [
        "Allowlist scheme và host cần thiết trước khi mở URL.",
        "Không truyền URL do người dùng kiểm soát trực tiếp vào lời gọi mạng.",
    ],
    ("bandit", "b404"): [
        "Ưu tiên API thư viện thay cho subprocess khi có thể và giữ phạm vi import/lời gọi tối thiểu."
    ],
    ("bandit", "b603"): [
        "Truyền argv dạng danh sách, giữ shell=False và allowlist mọi giá trị có nguồn bên ngoài."
    ],
    ("zap", "10021"): [
        "Cấu hình gateway trả X-Content-Type-Options: nosniff nhất quán."
    ],
    ("zap", "90004-1"): [
        "Cấu hình Cross-Origin-Resource-Policy phù hợp tại gateway và áp dụng cho cả response lỗi."
    ],
    ("zap", "10049-1"): [
        "Giữ chính sách no-store cho dữ liệu nhạy cảm; chỉ thay đổi sau khi đã xác nhận yêu cầu cache."
    ],
    ("zap", "10049-3"): [
        "Đặt Cache-Control rõ ràng; dùng no-store/private nếu response có dữ liệu nhạy cảm."
    ],
}


class DeterministicNarrativeProvider:
    """Reproducible offline baseline; it is not a replacement for an LLM eval."""

    name = "deterministic-v1"

    def generate(self, requests: Sequence[NarrativeRequest]) -> NarrativeBatch:
        drafts: list[NarrativeDraft] = []
        for request in requests:
            key = (request.tool.casefold(), request.rule_id.casefold())
            explanation = _EXPLANATIONS.get(
                key,
                (
                    f"Công cụ {request.tool} đã tạo {request.occurrence_count} "
                    "cảnh báo cùng rule. Đây là tín hiệu cần được review trong "
                    "ngữ cảnh source và cấu hình thực tế."
                ),
            )
            verification = _VERIFICATION_STEPS.get(
                key,
                ["Review thủ công toàn bộ bằng chứng scanner trước khi kết luận."],
            )
            remediation = _REMEDIATION_STEPS.get(key)
            if remediation is None:
                remediation = _knowledge_remediation(request) or [
                    "Áp dụng thay đổi hẹp nhất sau khi đã xác nhận cảnh báo là hợp lệ."
                ]
            drafts.append(
                NarrativeDraft(
                    group_id=request.group_id,
                    explanation=explanation,
                    verification_steps=verification,
                    remediation_steps=remediation,
                )
            )
        return NarrativeBatch(findings=drafts)


def _knowledge_remediation(request: NarrativeRequest) -> list[str]:
    steps: list[str] = []
    for context in request.knowledge_contexts:
        for step in context.remediation:
            cleaned = step.strip()
            if cleaned and cleaned not in steps:
                steps.append(cleaned)
            if len(steps) == 3:
                return steps
    return steps


def load_system_prompt() -> str:
    return (
        files("security_pipeline.analysis")
        .joinpath("prompts/security_analysis_system.md")
        .read_text(encoding="utf-8")
    )


class OpenAINarrativeProvider:
    """OpenAI Responses API provider using Pydantic Structured Outputs."""

    def __init__(
        self,
        *,
        model: str = "gpt-5.6-sol",
        api_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        if not model.strip():
            raise ProviderError("OpenAI model must not be empty")
        self.model = model.strip()
        self.name = f"openai:{self.model}"
        if client is not None:
            self._client = client
            return
        if not api_key:
            raise ProviderError(
                "OPENAI_API_KEY is required when --provider openai is selected"
            )
        try:
            from openai import OpenAI
        except ImportError as error:
            raise ProviderError(
                "Install the agent dependency with: pip install -e .[agent]"
            ) from error
        self._client = OpenAI(api_key=api_key)

    def generate(self, requests: Sequence[NarrativeRequest]) -> NarrativeBatch:
        payload = {"groups": [request.model_dump(mode="json") for request in requests]}
        try:
            response = self._client.responses.parse(
                model=self.model,
                input=[
                    {"role": "system", "content": load_system_prompt()},
                    {
                        "role": "user",
                        "content": json.dumps(
                            payload,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                    },
                ],
                text_format=NarrativeBatch,
                reasoning={"effort": "medium"},
                store=False,
            )
        except Exception as error:
            raise ProviderError(
                f"OpenAI request failed ({type(error).__name__})"
            ) from error
        parsed = getattr(response, "output_parsed", None)
        if parsed is None:
            raise ProviderError("OpenAI returned no parsed analysis output")
        if isinstance(parsed, NarrativeBatch):
            return parsed
        try:
            return NarrativeBatch.model_validate(parsed)
        except Exception as error:
            raise ProviderError("OpenAI returned an invalid analysis schema") from error
