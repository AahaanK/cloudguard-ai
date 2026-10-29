"""
CloudGuardAI - Secure Infrastructure as Code (IaC) Parser
Parses Terraform (.tf, .tf.json) and CloudFormation (.yaml, .json) into
a normalized resource graph. Treats all uploaded input as untrusted data:
  - Zero arbitrary code execution (Safe YAML loading, no eval/exec)
  - Detection and graceful reporting of unsupported constructs (modules, custom macros)
  - Malformed file handling with clean parsing error diagnostics
"""

import json
import re
import yaml
from typing import List, Dict, Any, Tuple, Optional

class NormalizedResource:
    def __init__(
        self,
        resource_id: str,
        resource_type: str,
        properties: Dict[str, Any],
        line_number: int = 1,
        service: Optional[str] = None,
        relationships: Optional[List[str]] = None
    ):
        self.resource_id = resource_id
        self.resource_type = resource_type.strip()
        self.properties = properties or {}
        self.line_number = line_number
        self.service = service or IaCParser.classify_service(self.resource_type)
        self.relationships = relationships or []

    def get(self, key: str, default: Any = None) -> Any:
        return self.properties.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "service": self.service,
            "relationships": self.relationships,
            "properties": self.properties,
            "line_number": self.line_number
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
    def _link_relationships(resources: List[NormalizedResource]):
        """Discovers cross-resource references (e.g. EC2 -> SG, Subnet -> VPC, Bucket Policy -> Bucket)."""
        id_map = {r.resource_id: r for r in resources}
        # Also map short names (e.g. for "aws_security_group.web_sg" allow "web_sg")
        short_name_map = {}
        for r in resources:
            parts = r.resource_id.split(".")
            if len(parts) > 1:
                short_name_map[parts[1]] = r.resource_id

        for r in resources:
            rel_set = set()
            # Inspect properties string and raw HCL
            raw_blob = str(r.properties.get("_raw_hcl", "")) + " " + json.dumps(
                {k: v for k, v in r.properties.items() if k != "_raw_hcl"}, default=str
            )
            for other_id in id_map:
                if other_id == r.resource_id:
                    continue
                # Full ID match
                if other_id in raw_blob:
                    rel_set.add(other_id)
                    continue
                # Short name match
                short_name = other_id.split(".")[-1]
                if short_name and short_name in raw_blob:
                    rel_set.add(other_id)
            r.relationships = sorted(list(rel_set))

    @staticmethod
    def parse(content: bytes, filename: str) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        """
        Parses untrusted IaC text safely.
        Returns: (resources, unsupported_constructs)
        """
        if not content:
            return [], []

        text = content.decode("utf-8", errors="replace")
        lower = filename.lower()
        unsupported: List[Dict[str, Any]] = []

        if lower.endswith(".tf"):
            IaCParser._detect_tf_unsupported(text, unsupported)
            resources = IaCParser._parse_terraform_hcl(text)
            IaCParser._link_relationships(resources)
            return resources, unsupported

        elif lower.endswith(".tf.json"):
            resources, unsupported = IaCParser._parse_terraform_json(text, unsupported)
            IaCParser._link_relationships(resources)
            return resources, unsupported

        elif lower.endswith(".yaml") or lower.endswith(".yml"):
            resources, unsupported = IaCParser._parse_cloudformation_yaml(text, unsupported)
            IaCParser._link_relationships(resources)
            return resources, unsupported

        elif lower.endswith(".json"):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    if "Resources" in data:
                        resources, unsupported = IaCParser._parse_cloudformation_dict(data, unsupported)
                        IaCParser._link_relationships(resources)
                        return resources, unsupported
                    elif "resource" in data:
                        resources, unsupported = IaCParser._parse_terraform_dict(data, unsupported)
                        IaCParser._link_relationships(resources)
                        return resources, unsupported
            except Exception:
                pass
            return [], [{"type": "MALFORMED_JSON", "description": "Unable to parse JSON syntax."}]

        # Fallback to HCL
        IaCParser._detect_tf_unsupported(text, unsupported)
        resources = IaCParser._parse_terraform_hcl(text)
        IaCParser._link_relationships(resources)
        return resources, unsupported

    @staticmethod
    def _detect_tf_unsupported(text: str, unsupported: List[Dict[str, Any]]):
        """Detects remote external modules and dynamic HCL blocks that cannot be statically parsed."""
        module_pattern = re.compile(r'module\s+"([^"]+)"\s*\{')
        for match in module_pattern.finditer(text):
            unsupported.append({
                "construct": f'module "{match.group(1)}"',
                "type": "EXTERNAL_TERRAFORM_MODULE",
                "message": f"External module '{match.group(1)}' referenced. Static analysis evaluates local configurations; external module contents were not inlined."
            })

        if "dynamic " in text:
            unsupported.append({
                "construct": "dynamic block",
                "type": "DYNAMIC_HCL_EXPRESSION",
                "message": "Dynamic block expression detected. CloudGuardAI evaluates static declarations."
            })

    @staticmethod
    def _parse_terraform_hcl(text: str) -> List[NormalizedResource]:
        """Regex-based HCL block parser for Terraform blueprints."""
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
                    props = IaCParser._extract_hcl_properties(raw_block)
                    props["_raw_hcl"] = raw_block
                    res_id = f"{current_res_type}.{current_res_name}"
                    resources.append(NormalizedResource(
                        resource_id=res_id,
                        resource_type=current_res_type,
                        properties=props,
                        line_number=current_start_line
                    ))
                    current_res_type = None
                    current_res_name = None
                    brace_depth = 0
                    block_lines = []

        return resources

    @staticmethod
    def _extract_hcl_properties(block_text: str) -> Dict[str, Any]:
        """Safely extracts key-value pairs from an HCL resource block."""
        props: Dict[str, Any] = {}
        for line in block_text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if "=" in line:
                parts = line.split("=", 1)
                key = parts[0].strip()
                val_raw = parts[1].strip().rstrip(",").strip('"')

                if val_raw.lower() == "true":
                    val = True
                elif val_raw.lower() == "false":
                    val = False
                elif val_raw.isdigit():
                    val = int(val_raw)
                else:
                    val = val_raw
                props[key] = val
        return props

    @staticmethod
    def _parse_cloudformation_yaml(text: str, unsupported: List[Dict[str, Any]]) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        """Safely parses CloudFormation YAML using SafeLoader."""
        try:
            yaml.add_multi_constructor("!", lambda loader, suffix, node: None, Loader=yaml.SafeLoader)
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return IaCParser._parse_cloudformation_dict(data, unsupported)
        except Exception as e:
            unsupported.append({
                "construct": "YAML Syntax",
                "type": "MALFORMED_YAML",
                "message": f"YAML parser encountered syntax error: {str(e)}"
            })
        return [], unsupported

    @staticmethod
    def _parse_cloudformation_dict(data: Dict[str, Any], unsupported: List[Dict[str, Any]]) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        resources: List[NormalizedResource] = []
        cfn_resources = data.get("Resources", {})
        if not isinstance(cfn_resources, dict):
            return [], unsupported

        for res_name, res_def in cfn_resources.items():
            if not isinstance(res_def, dict):
                continue
            res_type = res_def.get("Type", "Unknown")
            if res_type.startswith("Custom::"):
                unsupported.append({
                    "construct": res_type,
                    "type": "CFN_CUSTOM_RESOURCE",
                    "message": f"Custom CloudFormation macro or Lambda resource '{res_name}' skipped."
                })
                continue

            props = res_def.get("Properties", {})
            resources.append(NormalizedResource(
                resource_id=res_name,
                resource_type=res_type,
                properties=props if isinstance(props, dict) else {},
                line_number=1
            ))
        return resources, unsupported

    @staticmethod
    def _parse_terraform_dict(data: Dict[str, Any], unsupported: List[Dict[str, Any]]) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
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
                            line_number=1
                        ))
        return resources, unsupported

    @staticmethod
    def _parse_terraform_json(text: str, unsupported: List[Dict[str, Any]]) -> Tuple[List[NormalizedResource], List[Dict[str, Any]]]:
        try:
            data = json.loads(text)
            return IaCParser._parse_terraform_dict(data, unsupported)
        except Exception as e:
            unsupported.append({
                "construct": "JSON Syntax",
                "type": "MALFORMED_JSON",
                "message": f"JSON syntax error: {str(e)}"
            })
            return [], unsupported
