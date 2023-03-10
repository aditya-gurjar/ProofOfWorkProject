import unittest
from tests.gossip import GossipTest
# from tests.synchrony_start import SynchronyStartTest
# from tests.synchrony_rounds import SynchronyRoundsTest
# from tests.synchrony_sends import SynchronySendsTest
# from tests.ba_proposals import BAProposalsTest
# from tests.ba_votes import BAVotesTest
# from tests.ba_output import BAOutputTest

# Test for (3) - gossip
suite = unittest.TestLoader().loadTestsFromTestCase(GossipTest)
unittest.TextTestRunner(verbosity=2).run(suite)

# Test for (1.1) - synchrony_start
# suite = unittest.TestLoader().loadTestsFromTestCase(SynchronyStartTest)
# unittest.TextTestRunner(verbosity=2).run(suite)

# # Test for (1.2) - synchrony_rounds
# suite = unittest.TestLoader().loadTestsFromTestCase(SynchronyRoundsTest)
# unittest.TextTestRunner(verbosity=2).run(suite)

# # Test for (1.3) - synchrony_rounds
# suite = unittest.TestLoader().loadTestsFromTestCase(SynchronySendsTest)
# unittest.TextTestRunner(verbosity=2).run(suite)

# # Test for (1.1) - ba_proposals
# suite = unittest.TestLoader().loadTestsFromTestCase(BAProposalsTest)
# unittest.TextTestRunner(verbosity=2).run(suite)

# # Test for (1.2) - ba_votes
# suite = unittest.TestLoader().loadTestsFromTestCase(BAVotesTest)
# unittest.TextTestRunner(verbosity=2).run(suite)

# # Test for (1.3) - ba_output
# suite = unittest.TestLoader().loadTestsFromTestCase(BAOutputTest)
# unittest.TextTestRunner(verbosity=2).run(suite)

