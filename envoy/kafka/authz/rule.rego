package envoy.kafka.authz

    import input.attributes.request.http as http_request
    import input.parsed_path

    default allow = false

    # =====================================================
    # The following construct represents an OR in Rego
    # Basically we're saying that if one of the conditions
    # listed in the deny clause is true, we can validate
    # the request

    allow {
        not deny
    }

    deny {
        not allow_consumer_group
        not allow_producer_group
        not allow_admin_group
        not allow_health
        not allow_schemas
        not allow_subjects
    }
    
    # =====================================================


    # HEALTH CHECK STUFF
    allow_health {
        parsed_path[0] == "health"
        http_request.method == "GET"
    }

    # SCHEMA REGISTRY STUFF
    allow_schemas {
        parsed_path[0] == "schemas"        
    }
    allow_subjects {
        parsed_path[0] == "subjects"        
    }
    
    # ALLOW CONSUME
    allow_consumer_group {
        is_consumer_operation
        is_consumer_group
    }
         
    # ALLOW PUBLISH     
    allow_producer_group {
        is_producer_operation
        is_producer_group
    }

    # ALLOW ADMIN
    allow_admin_group {
        is_admin_operation
        is_admin_group
    }

    ###############################################################################
    # Groups and their helper rules
    ###############################################################################

    consumer_group = ["other-user", "read-user", "admin-user", "confluent-schema-registry"]
    producer_group = ["bridge-user", "write-user", "admin-user", "confluent-schema-registry"]
    admin_group = ["dean", "admin-user", "confluent-schema-registry"]
    

    is_consumer_group {
        consumer_group[_] == principal.name
    }

    is_producer_group {
        producer_group[_] == principal.name        
    }

    is_admin_group {
        admin_group[_] == principal.name
    }

    ###############################################################################
    # Operations and their helper rules
    ###############################################################################

    consumer_operations = {
                            "TOPIC": ["READ", "DESCRIBE"], 
                            "GROUP": ["READ", "DESCRIBE"]
                        }

    producer_operations = {
                            "TOPIC": ["WRITE", "IDEMPOTENT_WRITE", "DESCRIBE"]
                        }

    admin_operations = {
                        "TOPIC": ["READ", "WRITE", "CREATE", "DELETE", "ALTER", "DESCRIBE", "CLUSTER_ACTION", "DESCRIBE_CONFIGS", "ALTER_CONFIGS"], 
                        "GROUP": ["READ", "DELETE", "DESCRIBE"],
                        "CLUSTER": ["CREATE", "ALTER", "DESCRIBE", "CLUSTER_ACTION", "DESCRIBE_CONFIGS", "ALTER_CONFIGS"]
                        }

    is_consumer_operation {
        consumer_operations[input.action.resourcePattern.resourceType][_] == input.action.operation
    }

    is_producer_operation {
        producer_operations[input.action.resourcePattern.resourceType][_] == input.action.operation        
    }

    is_admin_operation {
        admin_operations[input.action.resourcePattern.resourceType][_] == input.action.operation
    }

    ###############################################################################
    # Helper rules for input processing
    ###############################################################################

    principal := {"fqn": parsed.CN, "name": cn_parts[0]} {
        parsed := parse_user(input.requestContext.principal.name)
        cn_parts := split(parsed.CN, ".")
    }
    else := {"fqn": "", "name": input.requestContext.principal.name}
    
    # principal := {"fqn": "", "name": input.requestContext.principal.name}
    
    parse_user(user) := {key: value |
       parts := split(user, ",")
       [key, value] := split(parts[_], "=")
    }