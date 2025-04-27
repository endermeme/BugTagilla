import argparse

parser = argparse.ArgumentParser(description='Test argparse conflict')

fuzzing_group = parser.add_argument_group('Fuzzing')
autorecon_group = parser.add_argument_group('AutoRecon')

fuzzing_group.add_argument('-ar', '--auto-recon-fuzzing',
                    type=str, help='auto recon',
                    metavar='domain.com')

autorecon_group.add_argument('--auto-recon', type=str, help='Perform automatic reconnaissance on target')

args = parser.parse_args()
print("Parser initialized successfully") 