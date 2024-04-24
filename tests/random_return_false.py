import random


def test_random_return_false():
    # Generate a random number between 1 and 10
    rand_num = random.randint(1, 10)

    # Return False with a probability of 1/10 (10%)
    if rand_num == 1:
        assert False
    else:
        assert True
