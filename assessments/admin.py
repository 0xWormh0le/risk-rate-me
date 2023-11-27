from django.contrib import admin
from .models import Topic, Question, Answer, Result


@admin.register(Topic)
class TopicAdmin(admin.ModelAdmin):
    class Meta:
        verbose_name_plural = "Topics"


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    class Meta:
        verbose_name_plural = "Questions"


@admin.register(Answer)
class AnswerAdmin(admin.ModelAdmin):
    class Meta:
        verbose_name_plural = "Answers"


@admin.register(Result)
class ResultAdmin(admin.ModelAdmin):
    class Meta:
        verbose_name_plural = "Results"
