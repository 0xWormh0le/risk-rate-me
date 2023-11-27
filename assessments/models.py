from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Topic(models.Model):
    assessment_type = models.IntegerField(default=0)
    name = models.CharField(blank=False, default="", max_length=64)
    description = models.CharField(blank=False, default="", max_length=1024)
    
    def __str__(self):
        fmt = "{name:s} - {desc:s}"
        return fmt.format(name=self.name, desc=self.description)


class Question(models.Model):
    topic = models.ForeignKey(Topic, on_delete=models.CASCADE)
    multiple = models.BooleanField(default=False)
    max_score = models.PositiveIntegerField()
    content = models.CharField(blank=False, default="", max_length=1024)
    recommendation = models.CharField(blank=True, default="", max_length=1024)

    def __str__(self):
        fmt = "{topic:s} : {content:s}"
        return fmt.format(topic=self.topic.name, content=self.content)


class Answer(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    content = models.CharField(blank=False, default="", max_length=1024)
    score = models.PositiveIntegerField(default=1)

    def __str__(self):
        fmt = "{content:s} : {score:d} - {topic:s} {question:s}"
        return fmt.format(content=self.content,
                          score=self.score,
                          topic=self.question.topic.name,
                          question=self.question.content)


class Result(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    answer = models.ForeignKey(Answer, on_delete=models.CASCADE)

    def __str__(self):
        fmt = "{user:s} : {score:d} : {answer:s} : {question:s}"
        return fmt.format(user=self.user.username,
                          score=self.answer.score,
                          answer=self.answer.content,
                          question=self.answer.question.content)
