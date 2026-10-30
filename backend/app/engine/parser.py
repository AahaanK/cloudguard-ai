"""
CloudGuardAI - Enhanced Infrastructure as Code (IaC) AST Parser
Parses Terraform (.tf, .tf.json) and CloudFormation (.yaml, .json) into
a normalized, interconnected resource topology graph.

Treats all uploaded input as untrusted data:
  - Zero arbitrary code execution (Safe YAML loading, zero eval/exec)
  - Variable declaration extraction and default value resolution
  - Dynamic block and nested block parsing
  - Cross-resource bidirectional relationship and dependency linking
  - Precise source location (line number tracking)
  - Explicit distinction between confirmed configurations and un-evaluable constructs
  - Graceful syntax error detection and diagnostics
"""

import json
import re
import yaml
from typing import List, Dict, Any, Tuple, Optional, Set

class NormalizedResource:
    def __init__(
        self,
        resource_id: str,
        resource_type: str,
        properties: Dict[str, Any],
        line_number: int = 1,
        service: Optional[str] = None,
        relationships: Optional[List[str]] = None,
        raw_snippet: Optional[str] = None,
        file_name: Optional[str] = None
    ):
        self.resource_id = resource_id
        self.resource_type = resource_type.strip()
        self.properties = properties or {}
        self.line_number = line_number
        self.service = service or IaCParser.classify_service(self.resource_type)
        self.relationships = relationships or []
        self.raw_snippet = raw_snippet or str(properties.get("_raw_hcl", ""))
        self.file_name = file_name
        self.unresolved_variables: Set[str] = set(self.properties.get("_unresolved_vars", []))

    def get(self, key: str, default: Any = None) -> Any:
        return self.properties.get(key, default)

    def is_property_explicitly_set(self, key: str) -> bool:
        """Returns True if the property was declared in the blueprint (not omitted)."""
        return key in self.properties

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "service": self.service,
            "relationships": self.relationships,
            "properties": {k: v for k, v in self.properties.items() if not k.startswith("_")},
            "line_number": self.line_number,
            "file_name": self.file_name
        }


class IaCParser:

    @staticmethod
    def classify_service(resource_type: str) -> str:
        """Categorizes raw resource type strings into standardized AWS service families."""
        t = resource_type.lower()
        if "security_group" in t or "securitygroup" in t:
            return "SECURITY_GROUP"
        if "s3" in t or "bucket" in t:
            return "S3"
        if "db_instance" in t or "rds" in t or "database" in t:
            return "RDS"
        if "ebs" in t or "volume" in t:
            return "EBS"
        if "vpc" in t or "subnet" in t or "internet_gateway" in t or "route_table" in t or "nat_gateway" in t:
            return "VPC"
        if "instance" in t or "ec2" in t or "launch_template" in t:
            return "EC2"
        if "iam" in t or "role" in t or "policy" in t or "user" in t:
            return "IAM"
        if "lambda" in t or "serverless" in t:
            return "LAMBDA"
        if "dynamodb" in t or "table" in t:
            return "DYNAMODB"
        if "api_gateway" in t or "apigateway" in t:
            return "API_GATEWAY"
        return "OTHER_AWS"

    @staticmethod
    def parse(content: bytes, filename: str) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        """
        Parses untrusted IaC text safely.
        Returns: (resources, unsupported_constructs)
        """
        if not content or len(content.strip()) == 0:
            return [], []

        text = content.decode("utf-8", errors="replace")
        lower = filename.lower()
        unsupported: List[Dict[str, Any]] = []

        if lower.endswith(".tf"):
            IaCParser._detect_tf_unsupported(text, unsupported)
            resources = IaCParser._parse_terraform_hcl(text, filename)
            IaCParser._link_relationships(resources)
            return resources, unsupported

        elif lower.endswith(".tf.json"):
            resources, unsupported = IaCParser._parse_terraform_json(text, unsupported, filename)
            IaCParser._link_relationships(resources)
            return resources, unsupported

        elif lower.endswith(".yaml") or lower.endswith(".yml"):
            resources, unsupported = IaCParser._parse_cloudformation_yaml(text, unsupported, filename)
            IaCParser._link_relationships(resources)
            return resources, unsupported

        elif lower.endswith(".json"):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    if "Resources" in data:
                        resources, unsupported = IaCParser._parse_cloudformation_dict(data, unsupported, filename)
                        IaCParser._link_relationships(resources)
                        return resources, unsupported
                    elif "resource" in data:
                        resources, unsupported = IaCParser._parse_terraform_dict(data, unsupported, filename)
                        IaCParser._link_relationships(resources)
                        return resources, unsupported
            except Exception as e:
                return [], [{
                    "construct": "JSON Syntax",
                    "type": "MALFORMED_JSON",
                    "message": f"Malformed JSON syntax: {str(e)}"
                }]
            return [], [{"construct": "JSON Syntax", "type": "MALFORMED_JSON", "message": "Unable to identify valid Terraform or CloudFormation JSON schema."}]

        # Fallback to HCL parser
        IaCParser._detect_tf_unsupported(text, unsupported)
        resources = IaCParser._parse_terraform_hcl(text, filename)
        IaCParser._link_relationships(resources)
        return resources, unsupported

    @staticmethod
    def _detect_tf_unsupported(text: str, unsupported: List[Dict[str, Any]]):
        """Detects remote external modules and notifies of static local evaluation."""
        module_pattern = re.compile(r'module\s+"([^"]+)"\s*\{')
        for match in module_pattern.finditer(text):
            unsupported.append({
                "construct": f'module "{match.group(1)}"',
                "type": "EXTERNAL_TERRAFORM_MODULE",
                "message": f"External module '{match.group(1)}' referenced. Local configurations evaluated statically; external registry contents are not inlined."
            })

    @staticmethod
    def _extract_tf_variables(text: str) -> Dict[str, Any]:
        """Extracts variable default declarations to enable static reference resolution."""
        variables: Dict[str, Any] = {}
        var_pattern = re.compile(r'variable\s+"([^"]+)"\s*\{([^}]*)\}', re.MULTILINE | re.DOTALL)
        for match in var_pattern.finditer(text):
            var_name = match.group(1)
            body = match.group(2)
            default_match = re.search(r'default\s*=\s*(.*)', body)
            if default_match:
                val_raw = default_match.group(1).strip().strip('"\'')
                if val_raw.lower() == "true":
                    val = True
                elif val_raw.lower() == "false":
                    val = False
                elif val_raw.isdigit():
                    val = int(val_raw)
                else:
                    val = val_raw
                variables[var_name] = val
        return variables

    @staticmethod
    def _parse_terraform_hcl(text: str, filename: str) -> List[NormalizedResource]:
        """
        Parses Terraform HCL into NormalizedResources.
        Extracts variable defaults, resolves variable references, parses nested blocks,
        and identifies line numbers.
        """
        variables = IaCParser._extract_tf_variables(text)
        resources: List[NormalizedResource] = []
        lines = text.split("\n")
        resource_pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')

        current_res_type = None
        current_res_name = None
        current_start_line = 1
        brace_depth = 0
        block_lines = []

        for line_idx, line in enumerate(lines, start=1):
            if not current_res_type:
                match = resource_pattern.search(line)
                if match:
                    current_res_type = match.group(1)
                    current_res_name = match.group(2)
                    current_start_line = line_idx
                    brace_depth = line.count("{") - line.count("}")
                    block_lines = [line]
            else:
                brace_depth += line.count("{") - line.count("}")
                block_lines.append(line)
                if brace_depth <= 0:
                    raw_block = "\n".join(block_lines)
                    props = IaCParser._extract_hcl_block_properties(raw_block, variables)
                    props["_raw_hcl"] = raw_block
                    res_id = f"{current_res_type}.{current_res_name}"
                    resources.append(NormalizedResource(
                        resource_id=res_id,
                        resource_type=current_res_type,
                        properties=props,
                        line_number=current_start_line,
                        raw_snippet=raw_block,
                        file_name=filename
                    ))
                    current_res_type = None
                    current_res_name = None
                    brace_depth = 0
                    block_lines = []

        return resources

    @staticmethod
    def _extract_hcl_block_properties(block_text: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses key-values, nested blocks, and dynamic blocks within an HCL resource.
        Resolves variable references where defaults are declared.
        """
        props: Dict[str, Any] = {}
        unresolved_vars: List[str] = []
        lines = block_text.split("\n")

        nested_blocks: Dict[str, List[Dict[str, Any]]] = {}
        in_nested_block = False
        nested_name = ""
        nested_depth = 0
        nested_lines: List[str] = []

        for line in lines[1:]:  # Skip resource header
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Nested block tracking (e.g. ingress { ... }, rule { ... }, dynamic "ingress" { ... })
            if not in_nested_block:
                block_match = re.match(r'(?:dynamic\s+"([^"]+)"|([a-zA-Z0-9_-]+))\s*\{', stripped)
                if block_match and "=" not in stripped.split("{")[0]:
                    nested_name = block_match.group(1) or block_match.group(2)
                    in_nested_block = True
                    nested_depth = stripped.count("{") - stripped.count("}")
                    nested_lines = [stripped]
                    continue

                if "=" in stripped:
                    parts = stripped.split("=", 1)
                    key = parts[0].strip()
                    val_raw = parts[1].strip().rstrip(",").strip()

                    # Check for variable reference
                    var_match = re.search(r'var\.([a-zA-Z0-9_-]+)', val_raw)
                    if var_match:
                        var_key = var_match.group(1)
                        if var_key in variables:
                            val = variables[var_key]
                        else:
                            val = val_raw.strip('"\'')
                            unresolved_vars.append(var_key)
                    else:
                        clean_val = val_raw.strip('"\'')
                        if clean_val.lower() == "true":
                            val = True
                        elif clean_val.lower() == "false":
                            val = False
                        elif clean_val.isdigit():
                            val = int(clean_val)
                        elif clean_val.startswith("[") and clean_val.endswith("]"):
                            # Parse inline list e.g. ["0.0.0.0/0"]
                            items = [i.strip().strip('"\'') for i in clean_val[1:-1].split(",") if i.strip()]
                            val = items
                        else:
                            val = clean_val

                    props[key] = val
            else:
                nested_depth += stripped.count("{") - stripped.count("}")
                nested_lines.append(stripped)
                if nested_depth <= 0:
                    sub_text = "\n".join(nested_lines)
                    # If this is a dynamic block, extract properties from content { ... }
                    if "content {" in sub_text:
                        content_body = sub_text.split("content {", 1)[-1].rsplit("}", 1)[0]
                        sub_props = IaCParser._extract_hcl_simple_props(content_body, variables)
                    else:
                        sub_props = IaCParser._extract_hcl_simple_props(sub_text, variables)

                    if nested_name not in nested_blocks:
                        nested_blocks[nested_name] = []
                    nested_blocks[nested_name].append(sub_props)

                    # Also promote common scalar block properties for convenience
                    if nested_name == "server_side_encryption_configuration":
                        props["server_side_encryption_configuration"] = sub_props or True
                    elif nested_name == "versioning":
                        props["versioning"] = sub_props

                    in_nested_block = False
                    nested_name = ""
                    nested_depth = 0
                    nested_lines = []

        # Merge nested blocks into props (e.g. props["ingress"] = [...])
        for b_name, b_list in nested_blocks.items():
            props[b_name] = b_list

        props["_unresolved_vars"] = unresolved_vars
        return props

    @staticmethod
    def _extract_hcl_simple_props(body: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """Simple property extractor for nested block contents."""
        sub: Dict[str, Any] = {}
        for line in body.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v_clean = v.strip().rstrip(",").strip('"\'')

                var_match = re.search(r'var\.([a-zA-Z0-9_-]+)', v_clean)
                if var_match and var_match.group(1) in variables:
                    v_clean = variables[var_match.group(1)]
                elif v_clean.lower() == "true":
                    v_clean = True
                elif v_clean.lower() == "false":
                    v_clean = False
                elif v_clean.isdigit():
                    v_clean = int(v_clean)
                elif v_clean.startswith("[") and v_clean.endswith("]"):
                    v_clean = [i.strip().strip('"\'') for i in v_clean[1:-1].split(",") if i.strip()]
                sub[k] = v_clean
        return sub

    @staticmethod
    def _link_relationships(resources: List[NormalizedResource]):
        """
        Builds a comprehensive bidirectional relationship graph across all parsed resources.
        Links:
          - EC2 -> Security Groups, Subnets, VPC, IAM Roles
          - Security Groups -> Security Group Rules, VPC
          - S3 Buckets -> Public Access Blocks, Server-Side Encryption Configurations, Bucket Policies
          - RDS Instances -> Subnet Groups, Security Groups, KMS Keys
          - IAM Roles -> Policies, Managed Policies, Attached Compute
        """
        id_map = {r.resource_id: r for r in resources}
        short_name_map = {}
        for r in resources:
            parts = r.resource_id.split(".")
            if len(parts) > 1:
                short_name_map[parts[1]] = r.resource_id

        # Pass 1: Discover references from properties & raw syntax
        for r in resources:
            rel_set = set(r.relationships)
            raw_blob = str(r.properties.get("_raw_hcl", "")) + " " + json.dumps(
                {k: v for k, v in r.properties.items() if not k.startswith("_")}, default=str
            )
            for other_id in id_map:
                if other_id == r.resource_id:
                    continue
                if other_id in raw_blob:
                    rel_set.add(other_id)
                    continue
                short_name = other_id.split(".")[-1]
                if short_name and short_name in raw_blob:
                    rel_set.add(other_id)
            r.relationships = sorted(list(rel_set))

        # Pass 2: Explicit bidirectional parent-child correlations
        for r in resources:
            r_type = r.resource_type.lower()
            p = r.properties

            # Dedicated S3 Public Access Block: aws_s3_bucket_public_access_block
            if "s3" in r_type and "public_access_block" in r_type:
                target_bucket = str(p.get("bucket", ""))
                for bucket_res in resources:
                    if "s3" in bucket_res.resource_type.lower() and "bucket" in bucket_res.resource_type.lower() and "public_access_block" not in bucket_res.resource_type.lower():
                        if bucket_res.resource_id == target_bucket or bucket_res.resource_id.split(".")[-1] in target_bucket or bucket_res.get("bucket") == target_bucket:
                            bucket_res.properties["_public_access_block"] = r
                            if r.resource_id not in bucket_res.relationships:
                                bucket_res.relationships.append(r.resource_id)
                            if bucket_res.resource_id not in r.relationships:
                                r.relationships.append(bucket_res.resource_id)

            # Dedicated S3 SSE Configuration: aws_s3_bucket_server_side_encryption_configuration
            if "s3" in r_type and "server_side_encryption" in r_type:
                target_bucket = str(p.get("bucket", ""))
                for bucket_res in resources:
                    if "s3" in bucket_res.resource_type.lower() and "bucket" in bucket_res.resource_type.lower() and "server_side_encryption" not in bucket_res.resource_type.lower():
                        if bucket_res.resource_id == target_bucket or bucket_res.resource_id.split(".")[-1] in target_bucket or bucket_res.get("bucket") == target_bucket:
                            bucket_res.properties["_server_side_encryption"] = r
                            if r.resource_id not in bucket_res.relationships:
                                bucket_res.relationships.append(r.resource_id)
                            if bucket_res.resource_id not in r.relationships:
                                r.relationships.append(bucket_res.resource_id)

            # Dedicated Security Group Rule: aws_security_group_rule
            if "security_group_rule" in r_type:
                target_sg = str(p.get("security_group_id", p.get("GroupId", "")))
                for sg_res in resources:
                    if "security_group" in sg_res.resource_type.lower() and "security_group_rule" not in sg_res.resource_type.lower():
                        if sg_res.resource_id in target_sg or sg_res.resource_id.split(".")[-1] in target_sg or sg_res.get("id") == target_sg:
                            if "_rules" not in sg_res.properties:
                                sg_res.properties["_rules"] = []
                            sg_res.properties["_rules"].append(r)
                            if r.resource_id not in sg_res.relationships:
                                sg_res.relationships.append(r.resource_id)
                            if sg_res.resource_id not in r.relationships:
                                r.relationships.append(sg_res.resource_id)

            # IAM Role Policy Attachment: aws_iam_role_policy or aws_iam_role_policy_attachment
            if "iam" in r_type and ("role_policy" in r_type or "policy_attachment" in r_type):
                target_role = str(p.get("role", p.get("RoleName", "")))
                for role_res in resources:
                    if "role" in role_res.resource_type.lower() and "policy" not in role_res.resource_type.lower():
                        if role_res.resource_id in target_role or role_res.resource_id.split(".")[-1] in target_role or role_res.get("name") == target_role:
                            if "_policies" not in role_res.properties:
                                role_res.properties["_policies"] = []
                            role_res.properties["_policies"].append(r)
                            if r.resource_id not in role_res.relationships:
                                role_res.relationships.append(r.resource_id)
                            if role_res.resource_id not in r.relationships:
                                r.relationships.append(role_res.resource_id)

    @staticmethod
    def _parse_cloudformation_yaml(text: str, unsupported: List[Dict[str, Any]], filename: str) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        """Safely parses CloudFormation YAML with custom tag constructor support."""
        try:
            # Custom constructor to safely absorb AWS CloudFormation tags like !Ref, !Sub, !GetAtt
            yaml.add_multi_constructor("!", lambda loader, suffix, node: getattr(node, "value", str(node)), Loader=yaml.SafeLoader)
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return IaCParser._parse_cloudformation_dict(data, unsupported, filename)
        except Exception as e:
            unsupported.append({
                "construct": "YAML Syntax",
                "type": "MALFORMED_YAML",
                "message": f"CloudFormation YAML syntax error: {str(e)}"
            })
        return [], unsupported

    @staticmethod
    def _parse_cloudformation_dict(data: Dict[str, Any], unsupported: List[Dict[str, Any]], filename: str) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        """Parses a CloudFormation JSON/YAML dictionary."""
        resources: List[NormalizedResource] = []
        cfn_resources = data.get("Resources", {})
        if not isinstance(cfn_resources, dict):
            return [], unsupported

        # Extract Parameter defaults
        parameters = {}
        for p_name, p_def in data.get("Parameters", {}).items():
            if isinstance(p_def, dict) and "Default" in p_def:
                parameters[p_name] = p_def["Default"]

        for res_name, res_def in cfn_resources.items():
            if not isinstance(res_def, dict):
                continue
            res_type = res_def.get("Type", "Unknown")
            if res_type.startswith("Custom::"):
                unsupported.append({
                    "construct": res_type,
                    "type": "CFN_CUSTOM_RESOURCE",
                    "message": f"Custom CloudFormation resource '{res_name}' skipped (static evaluation)."
                })
                continue

            props = res_def.get("Properties", {})
            props_clean = props if isinstance(props, dict) else {}
            # Attach parameter defaults context
            props_clean["_cfn_parameters"] = parameters

            resources.append(NormalizedResource(
                resource_id=res_name,
                resource_type=res_type,
                properties=props_clean,
                line_number=1,
                file_name=filename
            ))
        return resources, unsupported

    @staticmethod
    def _parse_terraform_dict(data: Dict[str, Any], unsupported: List[Dict[str, Any]], filename: str) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        """Parses a Terraform JSON dictionary."""
        resources: List[NormalizedResource] = []
        res_blocks = data.get("resource", {})
        if isinstance(res_blocks, dict):
            for res_type, instances in res_blocks.items():
                if isinstance(instances, dict):
                    for inst_name, props in instances.items():
                        resources.append(NormalizedResource(
                            resource_id=f"{res_type}.{inst_name}",
                            resource_type=res_type,
                            properties=props if isinstance(props, dict) else {},
                            line_number=1,
                            file_name=filename
                        ))
        return resources, unsupported

    @staticmethod
    def _parse_terraform_json(text: str, unsupported: List[Dict[str, Any]], filename: str) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        try:
            data = json.loads(text)
            return IaCParser._parse_terraform_dict(data, unsupported, filename)
        except Exception as e:
            unsupported.append({
                "construct": "JSON Syntax",
                "type": "MALFORMED_JSON",
                "message": f"JSON syntax error: {str(e)}"
            })
            return [], unsupported
