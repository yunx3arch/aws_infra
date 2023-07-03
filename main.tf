terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region  = var.region
  profile = "dev"
}

resource "aws_vpc" "main" {
  provider         = aws
  cidr_block       = "10.10.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "csye6225-vpc"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "csye6225-gateway"
  }
}

resource "aws_subnet" "public_subnets" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(var.public_subnet_cidrs, count.index)
  availability_zone = element(var.azs, count.index)

  tags = {
    Name = "Public Subnet ${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnets" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(var.private_subnet_cidrs, count.index)
  availability_zone = element(var.azs, count.index)

  tags = {
    Name = "Private Subnet ${count.index + 1}"
  }
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "Public Route Table"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "Private Route Table"
  }
}

resource "aws_route_table_association" "public_subnet_asso" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = element(aws_subnet.public_subnets[*].id, count.index)
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "private_subnet_asso" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = element(aws_subnet.private_subnets[*].id, count.index)
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_security_group" "app_sg" {
  name_prefix = "app-sg-"

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer_sg.id]
  }

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer_sg.id]
  }

  egress {
    description      = "HTTP"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  vpc_id = aws_vpc.main.id

  tags = {
    Name = "App Security Group"
  }
}

resource "aws_security_group" "database" {

  depends_on  = [aws_vpc.main, aws_security_group.app_sg]
  name        = "database"
  description = "security group for the database"
  vpc_id      = aws_vpc.main.id

  ingress = [
    {
      description      = "MYSQL"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = [aws_vpc.main.cidr_block]
      security_groups  = [aws_security_group.app_sg.id]
      self             = false
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
    }
  ]
  tags = {
    Name = "database"
  }
}

#db parameter group
resource "aws_db_parameter_group" "rds-pg" {
  name   = "rds-pg"
  family = "mysql5.7"
}
resource "aws_db_subnet_group" "rds-subnet" {
  name       = "rds-subnet"
  subnet_ids = [aws_subnet.public_subnets[0].id, aws_subnet.public_subnets[1].id, aws_subnet.public_subnets[2].id]

  tags = {
    Name = "rds-subnet"
  }
}
#db instance
resource "aws_db_instance" "csye6225" {

  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  db_name                = "csye6225"
  username               = "csye6225"
  password               = var.password
  db_subnet_group_name   = aws_db_subnet_group.rds-subnet.name
  parameter_group_name   = aws_db_parameter_group.rds-pg.name
  vpc_security_group_ids = [aws_security_group.database.id]

  multi_az                  = false
  identifier                = "csye6225"
  publicly_accessible       = false
  allocated_storage         = 10
  apply_immediately         = true
  backup_retention_period   = 5
  final_snapshot_identifier = true
  skip_final_snapshot       = true
  kms_key_id                = aws_kms_key.rdsKMSKeys.arn
  storage_encrypted = true
}

resource "aws_s3_bucket" "s3" {
  bucket        = "my-s3-${uuid()}"
  acl           = "private"
  force_destroy = true

  lifecycle_rule {
    id      = "long-term"
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3-encrypt" {
  bucket = aws_s3_bucket.s3.id

  rule {
    apply_server_side_encryption_by_default {
      # kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_iam_role" "ec2_access_role" {
  name = "EC2-CSYE6225-webapp"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    Name = "CodeDeployEC2ServiceRole"
  }
}

resource "aws_iam_policy" "policy" {
  name   = "WebAppS3"
  policy = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
              "s3:ListAllMyBuckets", 
              "s3:GetBucketLocation",
              "s3:GetObject",
              "s3:PutObject",
              "s3:deleteObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${aws_s3_bucket.s3.id}",
                "arn:aws:s3:::${aws_s3_bucket.s3.id}/*"
            ]
        }
    ]
    }
    EOF

}

resource "aws_iam_role_policy_attachment" "s3_policy" {
  role       = aws_iam_role.ec2_access_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_instance_profile" "s3_profile" {
  name = "s3_profile_3"
  role = aws_iam_role.ec2_access_role.name
}

locals {
  role_policy_arns = [
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
  ]
}
resource "aws_iam_role_policy_attachment" "cloudwatchpolicy" {
  # count = length(local.role_policy_arns)

  role       = aws_iam_role.ec2_access_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy" "cw_policy" {
  name = "EC2-Inline-Policy"
  role = aws_iam_role.ec2_access_role.name
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "ssm:GetParameter"
          ],
          "Resource" : "*"
        }
      ]
    }
  )
}


data "aws_ami" "my_ami" {
  most_recent = true

  filter {
    name   = "name"
    values = ["csye6225_*"]
  }
}

# resource "aws_instance" "web_server" {
#   ami                         = data.aws_ami.my_ami.id
#   instance_type               = "t2.micro"
#   key_name                    = "aws-demo-us-west-2"
#   security_groups             = [aws_security_group.app_sg.id]
#   subnet_id                   = element(aws_subnet.public_subnets.*.id, 0)
#   associate_public_ip_address = true
#   disable_api_termination     = false
#   iam_instance_profile = aws_iam_instance_profile.s3_profile.name
#   root_block_device {
#     volume_size           = 50
#     volume_type           = "gp2"
#     delete_on_termination = true
#   }
#   tags = {
#     Name = "Web Server"
#   }

#   user_data = <<-EOF
#     #!/bin/bash
#     sudo touch /etc/sysconfig/webappconfig
#     sudo chmod 777 /etc/sysconfig/webappconfig

#     echo "DB_HOSTNAME=${aws_db_instance.csye6225.address}" >> /etc/environment
#     echo "DB_USERNAME=csye6225" >> /etc/environment
#     echo "DB_PASSWORD=${var.password}" >> /etc/environment
#     echo "S3_BUCKET_NAME=${aws_s3_bucket.s3.bucket}" >> /etc/environment
#     echo "AWS_ACCESS_KEY=${var.AWS_ACCESS_KEY_ID}" >> /etc/environment
#     echo "AWS_SECRET_ACCESS_KEY=${var.AWS_SECRET_ACCESS_KEY}" >> /etc/environment
#     echo "REGION=${var.region}" >> /etc/environment

#     cd ~/code
#     rm package-lock.json
#     npm install
#     source /etc/environment
#     sudo mv /tmp/webapp.service /etc/systemd/system/webapp.service
#     sudo systemctl enable nginx
#     sudo systemctl start nginx
#     sudo systemctl daemon-reload
#     sudo systemctl enable webapp.service
#     sudo systemctl start webapp.service
#     EOF
# }

data "template_file" "user_data" {

  template = <<EOF

  #!/bin/bash
    sudo touch /etc/sysconfig/webappconfig
    sudo chmod 777 /etc/sysconfig/webappconfig


    echo "DB_HOSTNAME=${aws_db_instance.csye6225.address}" >> /etc/environment
    echo "DB_USERNAME=csye6225" >> /etc/environment
    echo "DB_PASSWORD=${var.password}" >> /etc/environment
    echo "S3_BUCKET_NAME=${aws_s3_bucket.s3.bucket}" >> /etc/environment
    echo "AWS_ACCESS_KEY=${var.AWS_ACCESS_KEY_ID}" >> /etc/environment
    echo "AWS_SECRET_ACCESS_KEY=${var.AWS_SECRET_ACCESS_KEY}" >> /etc/environment
    echo "REGION=${var.region}" >> /etc/environment

    cd ~/code
    rm package-lock.json
    npm install
    source /etc/environment
    # sudo mv /tmp/webapp.service /etc/systemd/system/webapp.service
    # sudo systemctl enable nginx
    # sudo systemctl start nginx
    # sudo systemctl daemon-reload
    # sudo systemctl enable webapp.service
    # sudo systemctl start webapp.service

 EOF

}

resource "aws_launch_template" "lt" {
  name_prefix   = "terraform-lc-example-"
  image_id      = data.aws_ami.my_ami.id
  instance_type = "t2.micro"
  key_name      = "aws-demo-us-west-2"

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.app_sg.id]
    subnet_id                   = element(aws_subnet.public_subnets.*.id, 0)
  }

  tags = {
    Name = "Web Server"
  }
  iam_instance_profile {
    name = aws_iam_instance_profile.s3_profile.name
  }
  lifecycle {
    create_before_destroy = true
  }
  user_data = base64encode(data.template_file.user_data.rendered)
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 50
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ebsKMSKeys.arn
    }
  }

}


resource "aws_autoscaling_group" "asg" {

  name                = "csye6225-asg-spring2023"
  max_size            = 3
  min_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = ["${aws_subnet.public_subnets[0].id}"]
  default_cooldown    = 60
  tag {
    key                 = "WebApp"
    value               = "Application"
    propagate_at_launch = true
  }

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }

  target_group_arns = [
    aws_lb_target_group.alb_tg.arn
  ]

}


resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name            = "WebServerScaleUpPolicy"
  adjustment_type = "ChangeInCapacity"
  policy_type     = "SimpleScaling"

  autoscaling_group_name = aws_autoscaling_group.asg.name
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.asg.name
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "scaleDown" {
  alarm_name                = "terraform-scaleDown"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = 60
  statistic                 = "Average"
  threshold                 = 3
  alarm_description         = "Scale Down when average cpu is below 3%"
  alarm_actions             = ["${aws_autoscaling_policy.WebServerScaleDownPolicy.arn}"]
  insufficient_data_actions = []
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }
}

resource "aws_cloudwatch_metric_alarm" "scaleUp" {
  alarm_name          = "terraform-scaleUp"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 5
  alarm_description   = "Scale Up when average cpu is above 5%"
  alarm_actions       = ["${aws_autoscaling_policy.WebServerScaleUpPolicy.arn}"]

  insufficient_data_actions = []
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }
}


resource "aws_lb" "lb" {

  name               = "csye6225-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer_sg.id]
  subnets            = aws_subnet.public_subnets.*.id
  tags = {
    Application = "WebApp"
  }

}

resource "aws_security_group" "load_balancer_sg" {
  name_prefix = "load_balancer_sg"
  vpc_id      = aws_vpc.main.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "LB Security Group"
  }
}

resource "aws_lb_target_group" "alb_tg" {
  port        = 3000
  protocol    = "HTTP"
  name        = "csye6225-lb-alb-tg"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"
  tags = {
    name = "albTargetGroup"
  }

  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 3
    interval            = 30
    path                = "/healthz"
    # port                = "3000"
    matcher = 200
    timeout = 5
  }

}

data "aws_acm_certificate" "issued" {
  domain   = "prod.makeentryleveljobsentrylevel.me"
  statuses = ["ISSUED"]
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.lb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = data.aws_acm_certificate.issued.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_tg.arn
  }

}

resource "aws_route53_record" "www" {
  name    = var.domain_name
  type    = "A"
  zone_id = var.zone_id

  alias {
    name                   = aws_lb.lb.dns_name
    zone_id                = aws_lb.lb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_kms_key" "ebsKMSKeys" {
  description              = "KMS Key for EBS"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"

  policy = jsonencode(
    {
        "Version": "2012-10-17",
        "Id": "kms-key-for-ebs",
        "Statement": [
            {
                "Sid": "Key for EBS",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::382300545992:root",
                    ]
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Add role",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                      "arn:aws:iam::382300545992:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"

                    ]
                },
                "Action": "kms:*",
                "Resource": "*"
            }
        ]
    }
  )
}

resource "aws_kms_key" "rdsKMSKeys" {
  description              = "KMS Key for RDS"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"

  policy = jsonencode(
    {
        "Version": "2012-10-17",
        "Id": "kms-key-for-ebs",
        "Statement": [
            {
                "Sid": "Key for RDS Instance",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::382300545992:root",
                    ]
                },
                "Action": "kms:*",
                "Resource": "*"
            }
        ]
    }
  )
}