##########
## Shared Data sources and locals
##########

locals {
  domain_name = "bananalab.dev"
  host_name = "atlantis"
  app_fqdn = "${local.host_name}.${data.aws_route53_zone.domain.name}"
  vpc_cidr = "10.0.0.0/16"
  availability_zones = ["us-west-1b", "us-west-1c"]
  private_subnet_cidrs = ["10.0.32.0/20", "10.0.48.0/20"]
  public_subnet_cidrs = ["10.0.0.0/20", "10.0.16.0/20"]
  atlantis_repo_allowlist = [ "github.com/bananalab/*" ]
  atlantis_gh_user = "rojopolis"
  atlantis_gh_token_secret = "arn:aws:secretsmanager:us-west-1:202151242785:secret:atlantis/gh_token-V8M4FD:ATLANTIS_GH_TOKEN::"
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_route53_zone" "domain" {
  name = local.domain_name
}

##########
## VPC CONFIG
##########
resource "aws_vpc" "this" {
  cidr_block = local.vpc_cidr
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
}

# Public subnet config
locals {
  public_subnets = zipmap(local.availability_zones, local.public_subnet_cidrs)
}

resource "aws_subnet" "public" {
  for_each          = local.public_subnets
  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = each.key
  map_public_ip_on_launch = true
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
}

resource "aws_route" "public" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_nat_gateway" "this" {
  for_each      = aws_subnet.public
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value.id
  depends_on    = [aws_internet_gateway.this]
}

resource "aws_eip" "nat" {
  for_each = aws_subnet.public
  vpc      = true
}

# Private subnet config
locals {
  private_subnets = zipmap(local.availability_zones, local.private_subnet_cidrs)
}

resource "aws_subnet" "private" {
  for_each          = local.private_subnets
  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = each.key
}

resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
}

resource "aws_route" "private" {
  for_each               = aws_route_table.private
  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[each.key].id
}

resource "aws_route_table_association" "private" {
  for_each       = aws_route.private
  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private[each.key].id
}

##########
## Retrieve GitHub Whitelist. 
##########

data "http" "github_meta" {
  url = "https://api.github.com/meta"
  request_headers = {
    Accept = "application/json"
  }
}

locals {
    hook_ips = jsondecode(data.http.github_meta.response_body).hooks
    hook_ips_v4 = [ for ip in local.hook_ips : ip if can(regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\/\\d{1,3}", ip))]
    hook_ips_v6 = [ for ip in local.hook_ips : ip if !contains(local.hook_ips_v4, ip)]
}

##########
## ECS Resources. 
##########

resource "aws_ecs_cluster" "this" {
  name = "atlantis"
}

resource "aws_ecs_task_definition" "atlantis" {
  family                   = "atlantis"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = jsonencode(
    [
      {
        name      = "atlantis"
        image     = "ghcr.io/runatlantis/atlantis:v0.21.0"
        essential = true
        portMappings = [{
          protocol      = "tcp"
          containerPort = 4141
          hostPort      = 4141
        }]
        secrets = [{
          name = "ATLANTIS_GH_TOKEN"
          valueFrom = local.atlantis_gh_token_secret
        }]
        environment = [
          {
            name  = "ATLANTIS_REPO_ALLOWLIST"
            value = join(",",local.atlantis_repo_allowlist)
          },
          {
            name  = "ATLANTIS_GH_USER"
            value = local.atlantis_gh_user
          },
          {
            name = "ATLANTIS_ATLANTIS_URL"
            value = "https://${local.app_fqdn}"
          }
        ]
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            awslogs-create-group = "true"
            awslogs-group = "atlantis"
            awslogs-region = data.aws_region.current.name
            awslogs-stream-prefix = "atlantis"
          }
        }
      }
    ]
  )
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "app-ecsTaskExecutionRole"

  assume_role_policy = <<-EOF
    {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "sts:AssumeRole",
            "Principal": {
              "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
          }
        ]
    }
    EOF
}

resource "aws_iam_role_policy_attachment" "ecs-task-execution-role-policy-attachment" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "administrator-access-policy-attachment" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_security_group" "service" {
  name        = "allow_lb_ports"
  description = "Allow LB ports"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "Atlantis from LB"
    from_port       = 4141
    to_port         = 4141
    protocol        = "tcp"
    security_groups = [aws_security_group.atlantis.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_ecs_service" "this" {
  name                               = "atlantis"
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.atlantis.arn
  desired_count                      = 1
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
  launch_type                        = "FARGATE"
  health_check_grace_period_seconds  = 120
  scheduling_strategy                = "REPLICA"

  network_configuration {
    security_groups  = [aws_security_group.service.id]
    subnets          = [for subnet in aws_subnet.private : subnet.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_alb_target_group.atlantis.arn
    container_name   = "atlantis"
    container_port   = 4141
  }
}

##########
## Load Balancer resources.
##########

resource "aws_security_group" "atlantis" {
  name        = "allow_atlantis_ports"
  description = "Allow atlantis ports"
  vpc_id      = aws_vpc.this.id

  ingress {
    description      = "HTTPS from github"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = local.hook_ips_v4
    ipv6_cidr_blocks = local.hook_ips_v6
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_lb" "this" {
  name               = "atlantis"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.atlantis.id]
  subnets            = [for subnet in aws_subnet.public : subnet.id]

  enable_deletion_protection = false
}

resource "aws_alb_target_group" "atlantis" {
  name        = "atlantis"
  port        = 4141
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this.id
  target_type = "ip"

  health_check {
    healthy_threshold   = "3"
    interval            = "30"
    protocol            = "HTTP"
    matcher             = "200"
    timeout             = "3"
    path                = "/"
    unhealthy_threshold = "2"
  }
}

resource "aws_alb_listener" "atlantis_https" {
  load_balancer_arn = aws_lb.this.id
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.this.certificate_arn

  default_action {
    type = "forward"
    forward {
      target_group {
        arn = aws_alb_target_group.atlantis.id
      }
    }
  }
}

resource "aws_route53_record" "atlantis" {
  zone_id = data.aws_route53_zone.domain.zone_id
  name    = local.app_fqdn
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}

##########
## Certificate Manager resources
##########

resource "aws_acm_certificate" "this" {
  domain_name       = local.app_fqdn
  validation_method = "DNS"
}

resource "aws_route53_record" "validation" {
  for_each = {
    for dvo in aws_acm_certificate.this.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.domain.zone_id
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for record in aws_route53_record.validation : record.fqdn]
}
