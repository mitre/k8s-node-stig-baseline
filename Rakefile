require 'rubocop/rake_task'
require 'rspec/core/rake_task'

namespace :inspec do
  desc 'Validate the profile with Cinc Auditor'
  task :check do
    sh 'bundle', 'exec', 'cinc-auditor', 'check', '.'
  end
end

RuboCop::RakeTask.new(:lint) do |task|
  task.options += %w[--display-cop-names --no-color --parallel]
end

RSpec::Core::RakeTask.new(:spec)

desc 'Run lint, regression tests, and profile validation'
task pre_commit_checks: [:lint, :spec, 'inspec:check']
