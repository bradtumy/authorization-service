package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bradtumy/authorization-service/pkg/policy"
	"github.com/bradtumy/authorization-service/pkg/policycompiler"
	"github.com/bradtumy/authorization-service/pkg/validator"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: policyctl <command> [args]")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "compile":
		if len(os.Args) < 3 {
			fmt.Println("usage: policyctl compile \"<rule>\"")
			os.Exit(1)
		}
		rule := os.Args[2]
		compiler := policycompiler.NewOpenAICompiler(os.Getenv("OPENAI_API_KEY"))
		yaml, err := compiler.Compile(rule)
		if err != nil {
			fmt.Println("compile error:", err)
			os.Exit(1)
		}
		fmt.Println(yaml)
	case "validate":
		if len(os.Args) < 3 {
			fmt.Println("usage: policyctl validate <file.yaml>")
			os.Exit(1)
		}
		if err := validator.ValidatePolicyFile(os.Args[2]); err != nil {
			fmt.Println("invalid policy:", err)
			os.Exit(1)
		}
		fmt.Println("policy is valid")
	case "explain":
		explainCmd := flag.NewFlagSet("explain", flag.ExitOnError)
		subject := explainCmd.String("subject", "", "subject")
		action := explainCmd.String("action", "", "action")
		resource := explainCmd.String("resource", "", "resource")
		if err := explainCmd.Parse(os.Args[2:]); err != nil {
			fmt.Println("failed to parse args:", err)
			os.Exit(1)
		}
		if *subject == "" || *action == "" || *resource == "" {
			fmt.Println("usage: policyctl explain --subject <subj> --action <act> --resource <res>")
			os.Exit(1)
		}
		store := policy.NewPolicyStore()
		if err := store.LoadPolicies("configs/policies.yaml"); err != nil {
			fmt.Println("failed to load policies:", err)
			os.Exit(1)
		}
		engine := policy.NewPolicyEngine(store)
		dec := engine.Evaluate(*subject, *resource, *action, nil)
		fmt.Printf("Policy ID: %s\n", dec.PolicyID)
		fmt.Printf("Reason: %s\n", dec.Reason)
		if len(dec.Trace) > 0 {
			fmt.Println("Trace:")
			for _, t := range dec.Trace {
				fmt.Println(" -", t)
			}
		}
	default:
		fmt.Println("usage: policyctl <compile|validate|explain> ...")
		os.Exit(1)
	}
}
