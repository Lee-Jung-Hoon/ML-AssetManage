import logging

# 테스트 중 부트스트랩/에러 로그가 출력을 어지럽히지 않게 한다 (assertLogs는 레벨을 직접 지정하므로 영향 없음).
logging.getLogger("app").setLevel(logging.CRITICAL)
