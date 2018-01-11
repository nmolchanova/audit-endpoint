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
