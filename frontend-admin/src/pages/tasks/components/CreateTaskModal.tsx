import { Button, Form, Input, Modal, Space, Switch, message } from 'antd'
import { useState } from 'react'

import { createTaskRecord, startTaskScan } from '@/services/tasks'

interface Props {
  open: boolean
  onCancel: () => void
  onCreated?: () => void
}

interface CreateTaskFormValues {
  name: string
  targets: string
  autoStart: boolean
}

const buildTaskId = () => {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }

  return `task-${Date.now()}`
}

const normalizeTargets = (value: string) =>
  value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean)

export default function CreateTaskModal({ open, onCancel, onCreated }: Props) {
  const [form] = Form.useForm<CreateTaskFormValues>()
  const [submitting, setSubmitting] = useState(false)

  const handleSubmit = async (values: CreateTaskFormValues) => {
    const targets = normalizeTargets(values.targets)
    const taskId = buildTaskId()

    setSubmitting(true)
    try {
      await createTaskRecord({
        id: taskId,
        name: values.name.trim(),
        targets,
      })

      if (values.autoStart) {
        try {
          await startTaskScan({
            taskId,
            urls: targets,
          })
          message.success('任务已创建并启动扫描')
        } catch (error) {
          console.error(error)
          message.warning('任务已创建，但启动扫描失败')
        }
      } else {
        message.success('任务已创建')
      }

      form.resetFields()
      onCreated?.()
      onCancel()
    } catch (error) {
      console.error(error)
      message.error('创建任务失败')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal
      title="创建任务"
      open={open}
      footer={null}
      onCancel={onCancel}
      destroyOnClose
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{ autoStart: true }}
        onFinish={handleSubmit}
      >
        <Form.Item
          name="name"
          label="任务名称"
          rules={[{ required: true, message: '请输入任务名称' }]}
        >
          <Input placeholder="例如：政务站点四月扫描" />
        </Form.Item>

        <Form.Item
          name="targets"
          label="目标 URL"
          rules={[
            { required: true, message: '请输入至少一个目标 URL' },
            {
              validator: async (_, value) => {
                if (normalizeTargets(value || '').length === 0) {
                  throw new Error('请输入至少一个目标 URL')
                }
              },
            },
          ]}
          extra="支持每行一个 URL，也支持使用逗号分隔。"
        >
          <Input.TextArea
            rows={6}
            placeholder={'https://example.com\nhttps://api.example.com'}
          />
        </Form.Item>

        <Form.Item
          name="autoStart"
          label="立即启动扫描"
          valuePropName="checked"
        >
          <Switch />
        </Form.Item>

        <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
          <Button onClick={onCancel}>取消</Button>
          <Button type="primary" htmlType="submit" loading={submitting}>
            创建任务
          </Button>
        </Space>
      </Form>
    </Modal>
  )
}
