SHELL := /bin/bash

# ===SETUP
BLUE      := $(shell tput -Txterm setaf 4)
GREEN     := $(shell tput -Txterm setaf 2)
TURQUOISE := $(shell tput -Txterm setaf 6)
WHITE     := $(shell tput -Txterm setaf 7)
YELLOW    := $(shell tput -Txterm setaf 3)
GREY      := $(shell tput -Txterm setaf 1)
RESET     := $(shell tput -Txterm sgr0)

SMUL      := $(shell tput smul)
RMUL      := $(shell tput rmul)

# Variable wrapper
define defw
	custom_vars += $(1)
	$(1) ?= $(2)
	export $(1)
	shell_env += $(1)="$$($(1))"
endef

# Variable wrapper for hidden variables
define defw_h
	$(1) := $(2)
	shell_env += $(1)="$$($(1))"
endef

# Add the following 'help' target to your Makefile
# And add help text after each target name starting with '\#\#'
# A category can be added with @category
HELP_FUN = \
	%help; \
	use Data::Dumper; \
	while(<>) { \
		if (/^([_a-zA-Z0-9\-\/]+)\s*:.*\#\#(?:@([a-zA-Z0-9\-\/_\s]+))?\t(.*)$$/ \
			|| /^([_a-zA-Z0-9\-\/]+)\s*:.*\#\#(?:@([a-zA-Z0-9\-\/]+))?\s(.*)$$/) { \
			$$c = $$2; $$t = $$1; $$d = $$3; \
			push @{$$help{$$c}}, [$$t, $$d, $$ARGV] unless grep { grep { grep /^$$t$$/, $$_->[0] } @{$$help{$$_}} } keys %help; \
		} \
	}; \
	for (sort keys %help) { \
		printf("${WHITE}%24s:${RESET}\n\n", $$_); \
		for (@{$$help{$$_}}) { \
			printf("%s%25s${RESET}%s  %s${RESET}\n", \
				( $$_->[2] eq "Makefile" || $$_->[0] eq "help" ? "${YELLOW}" : "${GREY}"), \
				$$_->[0], \
				( $$_->[2] eq "Makefile" || $$_->[0] eq "help" ? "${GREEN}" : "${GREY}"), \
				$$_->[1] \
			); \
		} \
		print "\n"; \
	}


default: help

.PHONY: help
help:: ##@Other Show this help.
	@echo ""
	@printf "%30s " "${BLUE}VARIABLES"
	@echo "${RESET}"
	@echo ""
	@printf "${BLUE}%25s${RESET}${TURQUOISE}  ${SMUL}%s${RESET}\n" $(foreach v, $(custom_vars), $v $(if $($(v)),$($(v)), ''))
	@echo ""
	@echo ""
	@echo ""
	@printf "%30s " "${YELLOW}TARGETS"
	@echo "${RESET}"
	@echo ""
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)

# === BEGIN USER OPTIONS ===
MFILECWD = $(shell pwd)

#space separated string array ->
$(eval $(call defw,NAMESPACES,keycloak-test))
$(eval $(call defw,DEFAULT_NAMESPACE,$(shell echo $(NAMESPACES) | awk '{print $$1}')))
$(eval $(call defw,DOMAINS,"localhost.com api.localhost.com login.localhost.com www.localhost.com"))
$(eval $(call defw,CLUSTER_NAME,$(shell basename $(MFILECWD))))
$(eval $(call defw,IP_ADDRESS,$(shell hostname -I | awk '{print $$1}')))
$(eval $(call defw,KUBECTL,kubectl))
$(eval $(call defw,OPENSSL,openssl))
$(eval $(call defw,CA_TLS_FILE,/etc/ssl/certs/localhost-ca.pem))
$(eval $(call defw,CA_TLS_KEY,/etc/ssl/certs/localhost-ca-key.pem))
$(eval $(call defw,TLS_FILE,/etc/ssl/certs/server.pem))
$(eval $(call defw,TLS_KEY,/etc/ssl/certs/server-key.pem))
$(eval $(call defw,TLS_CSR,/etc/ssl/certs/server.csr))

MAIN_DOMAIN=$(shell echo $(DOMAINS) | awk '{print $$1}')
SAN=$(shell echo $(DOMAINS) | sed 's/[^ ]* */DNS:&/g' | sed 's/\s\+/,/g') 

# === END USER OPTIONS ===

### DNS

.PHONY: dns/create
dns/insert: ##@dns Create dns
	@echo "Creating HOST DNS entries for the project ..."
	@for v in $(DOMAINS) ; do \
		echo $$v; \
		sudo sh -c "sed -zi \"/$$v/!s/$$/\n$(IP_ADDRESS)	$$v/\" /etc/hosts "; \
	done
	@echo "Completed..."

.PHONY: dns/remove
dns/remove: ##@dns Delete dns entries
	@echo "Removing HOST DNS entries ..."
	@for v in $(DOMAINS) ; do \
		echo $$v; \
		sudo sh -c "sed -i \"/$(IP_ADDRESS)	$$v/d\" /etc/hosts"; \
	done
	@echo "Completed..."

### CLUSTER

.PHONY: k8s/create-ns
k8s/create-ns: ##@cluster Create namespaces
	@echo "Creating Namespaces..."
	@for v in $(NAMESPACES) ; do \
		$(KUBECTL) create namespace $$v; \
	done
	@echo "Completed..."

.PHONY: k8s/provisioner
k8s/provisioner: ##@cluster Display hostname provisioner data
	$(KUBECTL) -n kube-system describe pod $$(kubectl get pods -n kube-system | grep hostpath | awk '{print $$1}')

.PHONY: k8s/debug
k8s/debug: ##@cluster Delete kubernetes jetstack cert-manager
	@echo "Starting netshoot in namespace $(DEFAULT_NAMESPACE)"
	$(KUBECTL) exec -it tmp-shell -n $(DEFAULT_NAMESPACE) -- /bin/bash || $(KUBECTL) run tmp-shell --rm -i --tty -n $(DEFAULT_NAMESPACE) --image nicolaka/netshoot -- /bin/bash

### CERTS

.PHONY: tls/create-ca
tls/create-ca: ##@tls Create self sign CA certs
	@echo "Creating key"
	$(OPENSSL) genrsa -out $(CA_TLS_KEY) 4096
	$(OPENSSL) req -x509 -new -nodes -key $(CA_TLS_KEY) -sha256 -days 1024 -subj "/C=UK/ST=London/O=Issuing authority/OU=IT management" -out $(CA_TLS_FILE)
	@echo "Created at: $(CA_TLS_FILE)"

.PHONY: tls/create-cert
tls/create-cert: ##@tls Create self sign certs for local machine
	@echo "Creating self signed certificate"
	$(OPENSSL) req -newkey rsa:2048 -nodes -keyout $(TLS_KEY) -subj "/C=UK/ST=London/L=London/O=Development/OU=IT/CN=$(MAIN_DOMAIN)" -out $(TLS_CSR)
	$(OPENSSL) x509 -req -extfile <(printf "subjectAltName=$(SAN),DNS:localhost,DNS:127.0.0.1") -days 365 -signkey $(CA_TLS_KEY) -in $(TLS_CSR) -out $(TLS_FILE)

.PHONY: tls/show-ca
tls/show-ca: ##@tls Show cert details
	@echo "Creating self signed certificate"
	$(OPENSSL) x509 -in $(CA_TLS_FILE) -text -noout

.PHONY: tls/show-cert
tls/show-cert: ##@tls Show cert details
	@echo "Creating self signed certificate"
	$(OPENSSL) x509 -in $(TLS_FILE) -text -noout

.PHONY: tls/trust-cert
tls/trust-cert: ##@tls Trust self signed cert by local browser
	@echo "Import self signed cert into user's truststore"
	@[ -d ~/.pki/nssdb ] || mkdir -p ~/.pki/nssdb
	@certutil -d sql:$$HOME/.pki/nssdb -A -n '$(MAIN_DOMAIN) cert authority' -i $(CA_TLS_FILE) -t TCP,TCP,TCP
	@certutil -d sql:$$HOME/.pki/nssdb -A -n '$(MAIN_DOMAIN)' -i $(TLS_FILE) -t P,P,P
	@echo "Import successful..."

### CERT-MAN

.PHONY: k8s/certman/deploy
k8s/certman/deploy: ##@certman Install and configure kubernetes jetstack cert-manager
	@echo "Installing certificate managerk"
	$(KUBECTL) apply -f https://github.com/jetstack/cert-manager/releases/download/v1.6.1/cert-manager.yaml
	@echo "Waiting for the cert manager to deploy"
	sleep 4m
	@echo "Deployed..."

.PHONY: k8s/certman/delete
k8s/certman/delete: ##@certman Delete kubernetes jetstack cert-manager
	@echo "Installing certificate managerk"
	$(KUBECTL) delete -f https://github.com/jetstack/cert-manager/releases/download/v1.6.1/cert-manager.yaml
	@echo "Completed..."

.PHONY: k8s/certman/create-ca
k8s/certman/create-ca: ##@certman Create ca-cert in the namsepaces from localhost-ca and ca-key 
	@echo "Creating the secrets using the CA keypair in all namespaces"
	@for v in $(NAMESPACES) ; do \
		sudo $(KUBECTL) -n $$v create secret generic ca-key-pair --from-file=tls.crt=$(CA_TLS_FILE) --from-file=tls.key=$(CA_TLS_KEY); \
	done
	@echo "Completed..."

.PHONY: k8s/certman/delete-ca
k8s/certman/delete-ca: ##@certman Install localhost.com ssl certs as a secret into namespaces
	@echo "Deleting ca certs from` secret"
	@for v in $(NAMESPACES) ; do \
		sudo $(KUBECTL) -n $$v delete secret ca-key-pair; \
	done

.PHONY: k8s/certman/create-issuer
k8s/certman/create-issuer: ##@certman Create cert issuer inside the selected namsepace from localhost-ca and ca-key 
	@echo "Creating certificate issuer"
	@for v in $(NAMESPACES) ; do \
		$(KUBECTL) -n $$v apply -f ./etc/cert-manager.yaml; \
	done
	@echo "Completed..."

.PHONY: k8s/certman/delete-issuer
k8s/certman/delete-issuer: ##@certman Delete cert issuer inside the selected namsepace from localhost-ca and ca-key 
	@echo "Deleting certificate issuer"
	@for v in $(NAMESPACES) ; do \
		$(KUBECTL) -n $$v delete -f ./etc/cert-manager.yaml; \
	done
	@echo "Completed..."

.PHONY: k8s/certman/create-cert
k8s/certman/create-cert: ##@certman Install localhost.com ssl certs as a secret into namespaces
	@echo "Importing localhost.com certs as secret"
	@for v in $(NAMESPACES) ; do \
		sudo $(KUBECTL) -n $$v create secret generic tls-cert-key-pair --from-file=tls.crt=$(TLS_FILE) --from-file=tls.key=$(TLS_KEY) --from-file=ca.crt=$(CA_TLS_FILE); \
	done
	@echo "Completed..."

.PHONY: k8s/certman/delete-cert
k8s/certman/delete-cert: ##@certman Install localhost.com ssl certs as a secret into namespaces
	@echo "Deleting localhost.com certs as secret"
	@for v in $(NAMESPACES) ; do \
		sudo $(KUBECTL) -n $$v delete secret tls-cert-key-pair; \
	done

### INGRESS

.PHONY: k8s/ingress/bindmainip
k8s/ingress/bindmainip: ##@ingress Change ingress to bind on the main ip only
	$(KUBECTL) get -n ingress configmap nginx-load-balancer-microk8s-conf -o json > /tmp/nginx-load.json && jq --slurp 'reduce .[] as $$item ({}; . * $$item)' /tmp/nginx-load.json ./etc/k8s/bind-address.json | kubectl -n ingress apply -f - && rm -rf /tmp/nginx-load.json

.PHONY: k8s/ingress/enableforward
k8s/ingress/enableforward: ##@ingress Enable IP forwarding
	$(KUBECTL) get -n ingress configmap nginx-load-balancer-microk8s-conf -o json > /tmp/nginx-load.json && jq --slurp 'reduce .[] as $$item ({}; . * $$item)' /tmp/nginx-load.json ./etc/k8s/ip-forward.json | kubectl -n ingress apply -f - && rm -rf /tmp/nginx-load.json

.PHONY: k8s/ingress/fixingress
k8s/ingress/fixingress: ##@ingress Enable some characters in ingress annotations
	$(KUBECTL) get -n ingress configmap nginx-load-balancer-microk8s-conf -o json > /tmp/nginx-load.json && jq --slurp 'reduce .[] as $$item ({}; . * $$item)' /tmp/nginx-load.json ./etc/k8s/annotation-value-word-blocklist.json | kubectl -n ingress apply -f - && rm -rf /tmp/nginx-load.json

.PHONY: k8s/ingress/fix-rolebind
k8s/ingress/fix-rolebind: ##@ingress Enable some characters in ingress annotations
	$(KUBECTL) get -n ingress role nginx-ingress-microk8s-role -o json > /tmp/nginx-load.json && jq --slurp 'reduce .[] as $$item ({}; . * $$item)' /tmp/nginx-load.json ./etc/k8s/configmap-update.json | kubectl -n ingress apply -f - && rm -rf /tmp/nginx-load.json


.PHONY: k8s/ingress/editconfigmap
k8s/ingress/editconfigmap: ##@ingress edit ingresses configmap
	$(KUBECTL) edit -n ingress configmap nginx-load-balancer-microk8s-conf


.PHONY: k8s/ingress/addip
k8s/ingress/addip: ##@ingress Add additional ip to loopback
	#sudo ifconfig lo:40 192.168.186.1 netmask 255.255.255.0 up
	sudo ifconfig lo 127.0.0.2 netmask 255.0.0.0 up


### DASHBOARD

.PHONY: dashboard/token
dashboard/token: ##@dashboard Enable kubernetes dashboard
	microk8s kubectl -n kube-system describe secret $$(microk8s kubectl -n kube-system get secret | grep admin-user | awk '{print $$1}')

.PHONY: dashboard/portforward
dashboard/portforward: ##@dashboard Port forward kubernetes dashboard 
	$(KUBECTL) port-forward -n kube-system service/kubernetes-dashboard 10443:443 --address 0.0.0.0

### MISC

.PHONY: init
init: k8s/create-namespaces k8s/certman/install k8s/certman/secret k8s/certman/issuer k8s/certman/install-cert sampledata dns/insert## Initialize the environment by creating cert manager
	@echo "Init completed"

.PHONY: synctime
synctime: ##@misc Sync VM time
	@sudo sudo timedatectl set-ntp off
	@sudo timedatectl set-ntp on
	@date

.PHONY: versions
versions: ##@misc Print the "imporant" tools versions out for easier debugging.
	@echo "=== BEGIN Version Info ==="
	@echo "Project name: ${CLUSTER_NAME}"
	@echo "Repo state: $$(git rev-parse --verify HEAD) (dirty? $$(if git diff --quiet; then echo 'NO'; else echo 'YES'; fi))"
	@echo "make: $$(command -v make)"
	@echo "kubectl: $$(command -v kubectl)"
	@echo "grep: $$(command -v grep)"
	@echo "cut: $$(command -v cut)"
	@echo "rsync: $$(command -v rsync)"
	@echo "openssl: $$(command -v openssl)"
	@echo "/dev/urandom: $$(if test -c /dev/urandom; then echo OK; else echo 404; fi)"
	@echo "=== END Version Info ==="

.EXPORT_ALL_VARIABLES:
