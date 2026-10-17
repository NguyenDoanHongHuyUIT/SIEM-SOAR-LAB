.PHONY: install lint test rules asl tf-validate build-rules suricata evaluate all
PY ?= python3

install:
	$(PY) -m pip install -r requirements-dev.txt

lint:
	ruff check .

test:
	pytest

rules:            ## lint + Suricata rule tests on the real engine
	$(PY) -m tools.rulesctl lint
	$(PY) -m tools.suricata_pcap_test   # Wazuh rules: tools.wazuh_logtest against a manager container (CI job wazuh-engine)

asl:              ## regenerate / check the Step Functions definition
	$(PY) -m tools.gen_asl

suricata:         ## needs `apt install suricata`: syntax check + pcap replay
	$(PY) -m tools.suricata_pcap_test

build-rules:
	$(PY) -m tools.rulesctl build --out dist --sha $$(git rev-parse HEAD)

tf-validate:
	terraform fmt -check -recursive infra
	for d in infra/bootstrap infra/envs/lab; do terraform -chdir=$$d init -backend=false -input=false && terraform -chdir=$$d validate; done
	terraform -chdir=infra/envs/lab test       # mocked-provider plan, no credentials needed

evaluate:
	$(PY) -m evaluation.evaluate

all: lint asl test rules tf-validate
