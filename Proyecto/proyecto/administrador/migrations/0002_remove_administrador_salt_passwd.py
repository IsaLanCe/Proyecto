# Generated by Django 4.2.16 on 2025-05-05 11:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('administrador', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='administrador',
            name='salt_passwd',
        ),
    ]
