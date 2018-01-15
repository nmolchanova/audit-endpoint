coreo_agent_selector_rule 'check-linux' do
  action :define
  timeout 120
  control 'check-linux' do
    describe command('uname') do
      its('stdout') { should eq "Linux\n" }
    end
  end
end
coreo_agent_audit_profile 'linux-benchmark' do
  action :define
  selectors ['check-linux']
  profile 'https://github.com/dev-sec/linux-baseline/archive/master.zip'
  timeout 120
end

coreo_agent_rule_runner 'agent-rules' do
  action :run
  rules []
  profiles ["linux-benchmark"]
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end
