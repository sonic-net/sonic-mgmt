import random


def test_random_return_false():
    # Generate a random number between 1 and 5
    rand_num = random.randint(1, 5)

    # Assert False with a probability of 1/5 (20%)
    if rand_num == 1:
        assert False
    else:
        assert True
