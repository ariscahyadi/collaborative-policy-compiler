import utils.policy_checker as policy_checker
import utils.rule2policy as rule2policy
import utils.policy2rule as policy2rule
import os


# Input Policy from two sites (Site-A and Site-B)

policyA = list(map(lambda x: [x], policy_checker.read_policy_input("data/policyA.txt")))
policyB = list(map(lambda x: [x], policy_checker.read_policy_input("data/policyB.txt")))


# Policy checking between sites

print("Inter-site Policy Checking ......")
matchedPolicy = list(policy_checker.inter_policy_matching(policyA, policyB))

print("The matching policy criterion are : ")
for i in range(len(matchedPolicy)):
    print("| %d | %s |" % (i, matchedPolicy[i]))
print("")


# Policy checking policy for each site

print("Intra-site Policy checking for invalid and overlap criterion ......")
print("")
print("Checking policy A criterion .... ")
validPolicy = policy_checker.intra_policy_check(policyA, matchedPolicy)
print("")
print("The valid policy criterion are: ")
for i in range(len(validPolicy)):
    print("| %d | %s |" % (i, validPolicy[i]))


# Generate policy from existing rules

print("")
print("Build policy from existing device rules ......")
print("")
print("Existing policy from the device rules are: ")

existingRule = rule2policy.rule_table_builder("data/existing_rules.txt")
ruleCriterion = rule2policy.rule_parser(existingRule)
rulePolicy = rule2policy.rule_to_policy_builder(ruleCriterion)


# Combine the matched policy and existing rules

print("")
print("The aggregate policy criterion from matched policy " "and existing rules are : ")
aggregatePolicy = rulePolicy + list(map(lambda x: [x], validPolicy))
compiledPolicy = policy_checker.intra_policy_check(list(aggregatePolicy), validPolicy)
for i in range(len(compiledPolicy)):
    print("| %d | %s |" % (i, compiledPolicy[i]))


# Optimize the policy

print("")
print("Optimizing the aggregated policy .....")
print("Optimized policy are: ")

optimizePolicy = policy2rule.policy_optimizer(aggregatePolicy)
optimizePolicy = list(map(lambda x: [x], optimizePolicy))


# Compiled Policy into New Rules

print("")
print("Generating the new rules for the device ...... ")
print("New Generated rules are: ")
print("")
print(policy2rule.policy_to_rule(list(optimizePolicy)))


# Save new rules into file

with open(os.path.join("data/", "generated_rules.txt"), "w") as output_file:
    output_file.write(policy2rule.policy_to_rule(list(optimizePolicy)))
