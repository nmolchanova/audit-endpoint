
coreo_agent_selector_rule 'check-redhat' do
  action :define
  timeout 30
  control 'check-redhat' do
    describe os.redhat? do
      it { should eq true }
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

coreo_agent_audit_rule 'check-linux-inventory' do
  action :define
  link "http://kb.cloudcoreo.com/"
  display_name "Check linux inventory"
  description "Check for linux servers."
  category "Inventory"
  suggested_action ""
  level "Low"
  selectors ['check-linux']
  control 'run-echo' do
    describe command('echo') do      
      it { should exist }      
    end
  end
  timeout 30
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

  
coreo_agent_audit_profile 'linux-benchmark' do
  action :define
  selectors ['check-linux']
  profile 'https://github.com/dev-sec/linux-baseline/archive/master.zip'
  timeout 120
end

coreo_agent_audit_profile 'linux-cis' do
  action :define
  selectors ['check-redhat']
  profile 'https://github.com/coolguru/cis-dil-benchmark/archive/master.zip'
  timeout 1
end

coreo_agent_rule_runner 'agent-rules' do
  action :run
  rules ${AUDIT_AGENT_RULES_ALERT_LIST}
  profiles ${AUDIT_AGENT_PROFILES_ALERT_LIST}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end
