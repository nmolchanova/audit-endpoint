coreo_agent_selector_rule 'check-echo' do
  action :define
  timeout 120
  control 'check if echo exist' do
    describe command('echo') do
      it { should exist }
    end
  end
end

coreo_agent_audit_rule 'echo-hello' do
  action :define
  link 'http://kb.cloudcoreo.com/'
  display_name 'Echo hello'
  description 'Echo hello and check for the output'
  category 'Security'
  suggested_action 'Make sure hello is the output.'
  level 'low'
  selectors ['check-echo']
  timeout 120
  control 'echo-hello' do
    impact 1.0
    describe command('echo hello') do
      its('stdout') { should eq "world\n" }
      its('stderr') { should eq '' }
      its('exit_status') { should eq 0 }
    end
  end
end

coreo_agent_selector_rule 'check-kubectl' do
    action :define
    timeout 30
    control 'check-kubectl' do
        describe command('kubectl') do
            it { should exist }
        end
    end
end

coreo_agent_audit_rule 'cis-kubernetes-benchmark-1-1-2' do
  action :define
  link 'http://kb.cloudcoreo.com/'
  display_name 'Ensure that the --anonymous-auth argument is set to false'
  description 'Disable anonymous requests to the API server.\n\nRationale: When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the API server. You should rely on authentication to authorize access and disallow anonymous requests.'
  category 'Security'
  suggested_action 'Disable anonymous requests to the API server.\n\nRationale: When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the API server. You should rely on authentication to authorize access and disallow anonymous requests.'
  level 'low'
  selectors ['check-kubectl']
  timeout 120
  control 'cis-kubernetes-benchmark-1.1.2' do
    title 'Ensure that the --anonymous-auth argument is set to false'
    desc "Disable anonymous requests to the API server.\n\nRationale: When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the API server. You should rely on authentication to authorize access and disallow anonymous requests."
    impact 1.0

    tag cis: 'kubernetes:1.1.2'
    tag level: 1

    describe processes('kube-apiserver').commands.to_s do
      it { should match(/--anonymous-auth=false/) }
    end
  end
end

coreo_agent_audit_rule 'cis-kubernetes-benchmark-1-1-4' do
  action :define
  link 'http://kb.cloudcoreo.com/'
  display_name 'Ensure that the --insecure-allow-any-token argument is not set'
  description 'Do not allow any insecure tokens\n\nRationale: Accepting insecure tokens would allow any token without actually authenticating anything. User information is parsed from the token and connections are allowed.'
  category 'Security'
  suggested_action 'None'
  level 'low'
  selectors ['check-kubectl']
  timeout 120
  control 'cis-kubernetes-benchmark-1.1.4' do
    title 'Ensure that the --insecure-allow-any-token argument is not set'
    desc "Do not allow any insecure tokens\n\nRationale: Accepting insecure tokens would allow any token without actually authenticating anything. User information is parsed from the token and connections are allowed."
    impact 1.0

    tag cis: 'kubernetes:1.1.4'
    tag level: 1

    describe processes('kube-apiserver').commands.to_s do
      it { should_not match(/--insecure-allow-any-token/) }
    end
  end
end

coreo_agent_audit_rule 'cis-kubernetes-benchmark-1-1-22' do
  action :define
  link 'http://kb.cloudcoreo.com/'
  display_name 'Ensure that the --kubelet-certificate-authority argument is set as appropriate'
  description 'Verify kubelet\'s certificate before establishing connection.\n\nRationale: The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching (through kubectl) to running pods, and using the kubelet’s port-forwarding functionality. These connections terminate at the kubelet’s HTTPS endpoint. By default, the apiserver does not verify the kubelet’s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run over untrusted and/or public networks.'
  category 'Security'
  suggested_action 'Disable anonymous requests to the API server.\n\nRationale: When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the API server. You should rely on authentication to authorize access and disallow anonymous requests.'
  level 'low'
  selectors ['check-kubectl']
  timeout 120
  control 'cis-kubernetes-benchmark-1.1.22' do
    title 'Ensure that the --kubelet-certificate-authority argument is set as appropriate'
    desc "Verify kubelet's certificate before establishing connection.\n\nRationale: The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching (through kubectl) to running pods, and using the kubelet’s port-forwarding functionality. These connections terminate at the kubelet’s HTTPS endpoint. By default, the apiserver does not verify the kubelet’s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run over untrusted and/or public networks."
    impact 1.0

    tag cis: 'kubernetes:1.1.22'
    tag level: 1

    describe processes('kube-apiserver').commands.to_s do
      it { should match(/--kubelet-certificate-authority=/) }
    end
  end
end

coreo_agent_selector_rule "check-mongod" do
  action :define
  timeout 30
  control 'check if mongod exist' do
    describe command('mongod') do
      it { should exist }
    end
  end
end

coreo_agent_audit_rule 'env-user-password' do
  action :define
  link "http://kb.cloudcoreo.com/"
  display_name "Do not store your user password in your ENV"
  description "Storing credentials in your ENV may easily expose them to an attacker. Prevent this at all costs."
  category "Security"
  suggested_action "Unset User password in your ENV"
  level "High"
  selectors ['check-mongod']
  control 'user-password' do
    describe command('env') do
      its('stdout') { should_not match(/^USER_PWD=/) }
    end
  end
  timeout 30
end

coreo_agent_selector_rule 'check-linux' do
  action :define
  timeout 120
  control 'check-linux' do
    describe command('uname') do
      its('stdout') { should eq "Linux\n" }
    end
  end
end

coreo_agent_selector_rule 'check-docker' do
  action :define
  timeout 30
  control 'check-docker' do
    describe command('docker') do
       it { should exist }
    end
  end
end

coreo_agent_audit_profile 'linux-benchmark' do
  action :define
  selectors ['check-linux']
  profile 'https://github.com/dev-sec/linux-baseline/archive/master.zip'
  timeout 120
end

coreo_agent_audit_profile 'linux-cis' do
  action :define
  selectors ['check-linux']
  profile 'https://github.com/coolguru/cis-dil-benchmark/archive/master.zip'
  timeout 120
end

coreo_agent_audit_profile 'docker-cis' do
  action :define
  selectors ['check-docker']
  profile 'https://github.com/coolguru/cis-docker-benchmark/archive/master.zip'
  timeout 120
end

coreo_agent_audit_profile 'windows-benchmark' do
  action :define
  profile 'https://github.com/dev-sec/windows-baseline/archive/master.zip'
  timeout 120
end

coreo_agent_audit_profile 'windows-patch-baseline' do
  action :define
  profile 'https://github.com/dev-sec/windows-patch-baseline/archive/master.zip'
  timeout 120
end

coreo_agent_audit_profile 'ssl-baseline' do
  action :define
  profile 'https://github.com/dev-sec/ssl-baseline/archive/master.zip'
  timeout 120
end

coreo_agent_rule_runner 'agent-rules' do
  action :run
  rules ${AUDIT_AGENT_RULES_ALERT_LIST}
  profiles ${AUDIT_AGENT_PROFILES_ALERT_LIST}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end
