require 'rubocop/rake_task'

namespace :inspec do
  desc 'Validate the profile with Cinc Auditor'
  task :check do
    sh 'bundle', 'exec', 'cinc-auditor', 'check', '.'
  end
end

RuboCop::RakeTask.new(:lint) do |task|
  task.options += %w[--display-cop-names --no-color --parallel]
end

desc 'Run lint and profile validation'
task pre_commit_checks: [:lint, 'inspec:check']
