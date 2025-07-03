# Copyright (c) 2025 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
#     https://opensource.org/licenses/Apache-2.0

import os
import unittest

try:
    from teamcity.unittestpy import TeamcityTestRunner

    teamcity = True
except ImportError:
    teamcity = False


def is_running_under_teamcity():
    # We export a different enviroment variable than teamcity package expects,
    # i.e. TEAMCITY_VERSION, hence a custom predicate to detect TeamCity
    # builds.
    return bool(os.getenv("CI"))


if __name__ == "__main__":
    if teamcity and is_running_under_teamcity():
        runner = TeamcityTestRunner()
    else:
        # Let unittest create it and _configure_ it that we honor the command
        # line options like --verbose.
        runner = None

    unittest.main(module=None, testRunner=runner, failfast=True)
